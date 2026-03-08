#!/usr/bin/env python3
"""
GitHub Client for CyberGhost-Ultra-Scanner
Asynchronous GitHub API client with rate limiting, retries, and comprehensive scanning
Optimized for low-resource systems with connection limiting and streaming responses
"""

import asyncio
import aiohttp
import base64
import time
import json
import zlib
from typing import List, Dict, Set, Optional, AsyncGenerator, Tuple, Any
from dataclasses import dataclass, field, asdict
from enum import Enum
from urllib.parse import urlparse, quote
import re
from datetime import datetime, timezone
import backoff
from collections import deque
import hashlib
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ============================================================================
# Data Models
# ============================================================================

class SecretSeverity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

@dataclass(slots=True)
class GitHubSecretMatch:
    """Represents a secret found in GitHub"""
    pattern_name: str
    secret_value: str
    file_path: str
    repo_name: str
    branch: str
    commit_sha: str
    commit_message: str
    commit_date: str
    author: str
    line_number: int
    severity: SecretSeverity
    url: str
    entropy_score: float = 0.0
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        return {
            'pattern_name': self.pattern_name,
            'secret_value': self.secret_value[:100] + '...' if len(self.secret_value) > 100 else self.secret_value,
            'file_path': self.file_path,
            'repo_name': self.repo_name,
            'branch': self.branch,
            'commit_sha': self.commit_sha[:8],  # Short SHA
            'commit_message': self.commit_message[:100],
            'commit_date': self.commit_date,
            'author': self.author,
            'line_number': self.line_number,
            'severity': self.severity.value,
            'url': self.url,
            'entropy_score': round(self.entropy_score, 2)
        }

@dataclass(slots=True)
class RateLimitInfo:
    """GitHub API rate limit information"""
    remaining: int
    limit: int
    reset_time: float  # Unix timestamp
    used: int = 0
    
    @property
    def reset_in(self) -> float:
        """Seconds until rate limit resets"""
        return max(0, self.reset_time - time.time())
    
    @property
    def is_exhausted(self) -> bool:
        """Check if rate limit is exhausted"""
        return self.remaining <= 0

# ============================================================================
# Pattern Database for GitHub Scanning
# ============================================================================

class GitHubPatternDatabase:
    """Pattern database optimized for GitHub scanning"""
    
    # Common file patterns to check for secrets
    SENSITIVE_FILES = {
        '.env', '.env.production', '.env.staging', '.env.local',
        'credentials.json', 'credentials.yaml', 'credentials.yml',
        'secrets.yml', 'secrets.yaml', 'secrets.json',
        'config.yml', 'config.yaml', 'config.json',
        'application.properties', 'application.yml', 'application.yaml',
        'database.yml', 'database.yaml',
        'wp-config.php', 'wp-config.php',
        'id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519',
        'private_key.pem', 'private.key', 'key.pem',
        '.npmrc', '.yarnrc', '.gemrc',
        '.pypirc', '.pypi.conf',
        '.netrc', '.s3cfg',
        'Dockerfile', 'docker-compose.yml',
        'kubeconfig', 'config.json',  # Kubernetes
        'terraform.tfvars', 'terraform.tfvars.json',
        '.aws/credentials', '.aws/config',
        '.azure/credentials', '.azure/config',
        '.gcp/credentials.json', '.gcp/config',
    }
    
    # Patterns for commit message analysis
    COMMIT_SECRET_PATTERNS = [
        (re.compile(r'(?i)(api[_-]?key|apikey|secret|token|password)[\s:]+[0-9a-zA-Z\-_]{16,}'), SecretSeverity.HIGH),
        (re.compile(r'(?i)removed (api ?key|secret|token|password)'), SecretSeverity.MEDIUM),
        (re.compile(r'(?i)accidentally committed (api ?key|secret)'), SecretSeverity.CRITICAL),
        (re.compile(r'[0-9a-f]{40,}'), SecretSeverity.MEDIUM),  # Long hex strings
        (re.compile(r'[A-Za-z0-9+/=]{40,}'), SecretSeverity.MEDIUM),  # Base64-like
    ]
    
    @classmethod
    def is_sensitive_file(cls, file_path: str) -> bool:
        """Check if file path indicates potential secrets"""
        file_path = file_path.lower()
        return any(
            sensitive in file_path or file_path.endswith(sensitive)
            for sensitive in cls.SENSITIVE_FILES
        )
    
    @classmethod
    def check_commit_message(cls, message: str) -> List[Tuple[str, SecretSeverity]]:
        """Check commit message for secret-related content"""
        matches = []
        for pattern, severity in cls.COMMIT_SECRET_PATTERNS:
            for match in pattern.finditer(message):
                matches.append((match.group(), severity))
        return matches

# ============================================================================
# GitHub API Client with Rate Limiting
# ============================================================================

class GitHubAPIClient:
    """Asynchronous GitHub API client with rate limiting and retries"""
    
    BASE_URL = "https://api.github.com"
    API_VERSION = "2022-11-28"
    
    def __init__(
        self,
        token: str,
        max_concurrent: int = 3,  # i3 optimized
        max_retries: int = 3,
        timeout: int = 30,
        user_agent: str = "CyberGhost-Ultra-Scanner/1.0"
    ):
        self.token = token
        self.max_concurrent = max_concurrent
        self.max_retries = max_retries
        self.timeout = timeout
        self.user_agent = user_agent
        
        # Rate limiting
        self.rate_limit = RateLimitInfo(
            remaining=5000,
            limit=5000,
            reset_time=time.time() + 3600
        )
        
        # Semaphore for connection limiting
        self.semaphore = asyncio.Semaphore(max_concurrent)
        
        # Request queue for rate limiting
        self.request_times = deque(maxlen=100)  # Track last 100 request times
        
        # Session (created in __aenter__)
        self.session: Optional[aiohttp.ClientSession] = None
    
    async def __aenter__(self):
        """Async context manager entry"""
        headers = {
            "Authorization": f"token {self.token}",
            "Accept": "application/vnd.github.v3+json",
            "X-GitHub-Api-Version": self.API_VERSION,
            "User-Agent": self.user_agent
        }
        
        timeout = aiohttp.ClientTimeout(
            total=self.timeout,
            connect=10,
            sock_read=self.timeout
        )
        
        connector = aiohttp.TCPConnector(
            limit=self.max_concurrent,
            limit_per_host=2,
            ttl_dns_cache=300,
            force_close=True,  # Prevent connection accumulation
            enable_cleanup_closed=True
        )
        
        self.session = aiohttp.ClientSession(
            headers=headers,
            timeout=timeout,
            connector=connector
        )
        
        # Initial rate limit check
        await self._update_rate_limit()
        
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    async def _update_rate_limit(self):
        """Fetch current rate limit status"""
        try:
            async with self.session.get(f"{self.BASE_URL}/rate_limit") as response:
                if response.status == 200:
                    data = await response.json()
                    core = data.get('resources', {}).get('core', {})
                    self.rate_limit.remaining = core.get('remaining', 0)
                    self.rate_limit.limit = core.get('limit', 5000)
                    self.rate_limit.reset_time = core.get('reset', 0)
        except Exception as e:
            logger.warning(f"Failed to update rate limit: {e}")
    
    async def _wait_for_rate_limit(self):
        """Wait if rate limit is exhausted"""
        if self.rate_limit.is_exhausted:
            wait_time = self.rate_limit.reset_in + 1
            if wait_time > 0:
                logger.warning(f"Rate limit exhausted. Waiting {wait_time:.0f}s")
                await asyncio.sleep(wait_time)
                await self._update_rate_limit()
    
    async def _throttle_if_needed(self):
        """Throttle requests to avoid hitting rate limits"""
        # Track request timing
        now = time.time()
        self.request_times.append(now)
        
        # If we've made many requests recently, slow down
        if len(self.request_times) >= 80:  # 80% of rate limit
            oldest = self.request_times[0]
            if now - oldest < 60:  # Less than a minute
                sleep_time = 60 - (now - oldest)
                if sleep_time > 0:
                    logger.debug(f"Throttling: sleeping {sleep_time:.2f}s")
                    await asyncio.sleep(sleep_time)
    
    @backoff.on_exception(
        backoff.expo,
        (aiohttp.ClientError, asyncio.TimeoutError),
        max_tries=3,
        max_time=30
    )
    async def _make_request(
        self,
        method: str,
        url: str,
        params: Optional[Dict] = None,
        headers: Optional[Dict] = None
    ) -> Tuple[int, Any]:
        """Make an API request with retries and rate limiting"""
        await self._wait_for_rate_limit()
        await self._throttle_if_needed()
        
        async with self.semaphore:  # Limit concurrent connections
            request_headers = headers or {}
            
            async with self.session.request(
                method, url, params=params, headers=request_headers
            ) as response:
                
                # Update rate limit from headers
                remaining = response.headers.get('X-RateLimit-Remaining')
                if remaining:
                    self.rate_limit.remaining = int(remaining)
                
                reset = response.headers.get('X-RateLimit-Reset')
                if reset:
                    self.rate_limit.reset_time = int(reset)
                
                # Handle rate limit exceeded
                if response.status == 403 and 'rate limit' in await response.text():
                    retry_after = int(response.headers.get('Retry-After', 60))
                    logger.warning(f"Rate limited. Waiting {retry_after}s")
                    await asyncio.sleep(retry_after)
                    return await self._make_request(method, url, params, headers)
                
                # Handle success
                if response.status == 200:
                    if response.headers.get('content-type') == 'application/json':
                        return response.status, await response.json()
                    return response.status, await response.text()
                
                # Handle other errors
                if response.status >= 400:
                    text = await response.text()
                    logger.error(f"GitHub API error {response.status}: {text}")
                    
                    # Retry on server errors
                    if response.status >= 500:
                        raise aiohttp.ClientError(f"Server error: {response.status}")
                
                return response.status, None
    
    async def get_repo_info(self, owner: str, repo: str) -> Optional[Dict]:
        """Get repository information"""
        url = f"{self.BASE_URL}/repos/{owner}/{repo}"
        status, data = await self._make_request('GET', url)
        return data if status == 200 else None
    
    async def get_branches(self, owner: str, repo: str) -> List[Dict]:
        """Get all branches"""
        url = f"{self.BASE_URL}/repos/{owner}/{repo}/branches"
        branches = []
        page = 1
        
        while True:
            status, data = await self._make_request(
                'GET', url, params={'page': page, 'per_page': 100}
            )
            
            if status != 200 or not data:
                break
            
            branches.extend(data)
            
            if len(data) < 100:
                break
            
            page += 1
        
        return branches
    
    async def get_commits(
        self,
        owner: str,
        repo: str,
        branch: str = 'main',
        since: Optional[str] = None,
        until: Optional[str] = None,
        max_commits: int = 100
    ) -> List[Dict]:
        """Get commits with pagination"""
        url = f"{self.BASE_URL}/repos/{owner}/{repo}/commits"
        commits = []
        page = 1
        per_page = min(100, max_commits)
        
        params = {
            'sha': branch,
            'page': page,
            'per_page': per_page
        }
        
        if since:
            params['since'] = since
        if until:
            params['until'] = until
        
        while len(commits) < max_commits:
            status, data = await self._make_request('GET', url, params=params)
            
            if status != 200 or not data:
                break
            
            commits.extend(data)
            
            if len(data) < per_page or len(commits) >= max_commits:
                break
            
            page += 1
            params['page'] = page
        
        return commits[:max_commits]
    
    async def get_commit_details(self, owner: str, repo: str, commit_sha: str) -> Optional[Dict]:
        """Get detailed commit information including diffs"""
        url = f"{self.BASE_URL}/repos/{owner}/{repo}/commits/{commit_sha}"
        
        headers = {
            'Accept': 'application/vnd.github.v3.diff'
        }
        
        status, data = await self._make_request('GET', url, headers=headers)
        
        if status == 200:
            return {
                'sha': commit_sha,
                'diff': data if isinstance(data, str) else None,
                'details': await self._get_commit_json(owner, repo, commit_sha)
            }
        
        return None
    
    async def _get_commit_json(self, owner: str, repo: str, commit_sha: str) -> Optional[Dict]:
        """Get commit details in JSON format"""
        url = f"{self.BASE_URL}/repos/{owner}/{repo}/commits/{commit_sha}"
        status, data = await self._make_request('GET', url)
        return data if status == 200 else None
    
    async def get_file_content(self, owner: str, repo: str, path: str, ref: str) -> Optional[str]:
        """Get file content at a specific ref"""
        url = f"{self.BASE_URL}/repos/{owner}/{repo}/contents/{path}"
        
        status, data = await self._make_request(
            'GET', url, params={'ref': ref}
        )
        
        if status == 200 and data and 'content' in data:
            try:
                content = base64.b64decode(data['content']).decode('utf-8', errors='ignore')
                return content
            except Exception as e:
                logger.debug(f"Failed to decode {path}: {e}")
        
        return None
    
    async def get_tree(self, owner: str, repo: str, branch: str, recursive: bool = True) -> List[Dict]:
        """Get repository tree"""
        # First get the branch to find the tree SHA
        branch_info = await self.get_branch(owner, repo, branch)
        if not branch_info:
            return []
        
        commit_sha = branch_info['commit']['sha']
        
        # Get the tree
        url = f"{self.BASE_URL}/repos/{owner}/{repo}/git/trees/{commit_sha}"
        params = {'recursive': '1'} if recursive else {}
        
        status, data = await self._make_request('GET', url, params=params)
        
        if status == 200 and data:
            return data.get('tree', [])
        
        return []
    
    async def get_branch(self, owner: str, repo: str, branch: str) -> Optional[Dict]:
        """Get branch information"""
        url = f"{self.BASE_URL}/repos/{owner}/{repo}/branches/{branch}"
        status, data = await self._make_request('GET', url)
        return data if status == 200 else None

# ============================================================================
# GitHub Scanner with Secret Detection
# ============================================================================

class GitHubScanner:
    """Main scanner class for GitHub repositories"""
    
    def __init__(
        self,
        api_client: GitHubAPIClient,
        entropy_threshold: float = 3.8,
        min_length: int = 10,
        max_file_size: int = 1024 * 1024,  # 1MB
    ):
        self.api = api_client
        self.entropy_threshold = entropy_threshold
        self.min_length = min_length
        self.max_file_size = max_file_size
        
        # Import patterns from main scanner (to be injected)
        self.patterns = []
        
        # Cache for processed items
        self.processed_commits: Set[str] = set()
        self.processed_files: Set[str] = set()
        
        # Statistics
        self.stats = {
            'commits_scanned': 0,
            'files_scanned': 0,
            'diffs_analyzed': 0,
            'api_calls': 0
        }
    
    def set_patterns(self, patterns: List):
        """Set regex patterns from main scanner"""
        self.patterns = patterns
    
    def calculate_entropy(self, data: str) -> float:
        """Calculate Shannon entropy"""
        if len(data) < self.min_length:
            return 0.0
        
        entropy = 0.0
        length = len(data)
        counts = [0] * 256
        
        for char in data.encode('utf-8', errors='ignore'):
            counts[char] += 1
        
        for count in counts:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        
        return entropy
    
    def scan_content(
        self,
        content: str,
        file_path: str,
        repo_name: str,
        branch: str,
        commit_sha: str,
        commit_message: str,
        commit_date: str,
        author: str,
        url: str
    ) -> List[GitHubSecretMatch]:
        """Scan file content for secrets"""
        matches = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            if len(line) < self.min_length:
                continue
            
            # Check regex patterns
            for pattern in self.patterns:
                for match in pattern.regex.finditer(line):
                    secret = match.group()
                    
                    # Calculate entropy for additional confidence
                    entropy = self.calculate_entropy(secret)
                    
                    matches.append(GitHubSecretMatch(
                        pattern_name=pattern.name,
                        secret_value=secret,
                        file_path=file_path,
                        repo_name=repo_name,
                        branch=branch,
                        commit_sha=commit_sha,
                        commit_message=commit_message,
                        commit_date=commit_date,
                        author=author,
                        line_number=line_num,
                        severity=pattern.severity,
                        url=url,
                        entropy_score=entropy
                    ))
            
            # Check for high entropy strings (potential custom secrets)
            words = re.findall(r'[A-Za-z0-9\-_=+/]{16,}', line)
            for word in words:
                entropy = self.calculate_entropy(word)
                if entropy >= self.entropy_threshold:
                    # Check if it's not a common string
                    if not self._is_common_string(word):
                        matches.append(GitHubSecretMatch(
                            pattern_name="High Entropy String",
                            secret_value=word,
                            file_path=file_path,
                            repo_name=repo_name,
                            branch=branch,
                            commit_sha=commit_sha,
                            commit_message=commit_message,
                            commit_date=commit_date,
                            author=author,
                            line_number=line_num,
                            severity=SecretSeverity.MEDIUM,
                            url=url,
                            entropy_score=entropy
                        ))
        
        return matches
    
    def _is_common_string(self, text: str) -> bool:
        """Check if string is common (not a secret)"""
        common = {
            'password', 'username', 'localhost', 'database', 'server',
            'true', 'false', 'null', 'undefined', 'function', 'class',
            'public', 'private', 'static', 'void', 'string', 'number',
            'github', 'gitlab', 'bitbucket', 'docker', 'kubernetes'
        }
        return text.lower() in common
    
    def scan_diff(
        self,
        diff: str,
        repo_name: str,
        branch: str,
        commit_sha: str,
        commit_message: str,
        commit_date: str,
        author: str,
        url: str
    ) -> List[GitHubSecretMatch]:
        """Scan commit diff for secrets"""
        matches = []
        
        # Parse diff to extract added lines
        added_lines = []
        current_file = None
        
        for line in diff.split('\n'):
            if line.startswith('+++ b/'):
                current_file = line[6:]  # Remove '+++ b/'
            elif line.startswith('+') and not line.startswith('+++'):
                if current_file and len(line) > 1:
                    added_lines.append((current_file, line[1:]))
        
        # Scan added lines
        for file_path, line_content in added_lines:
            if len(line_content) < self.min_length:
                continue
            
            # Check patterns
            for pattern in self.patterns:
                for match in pattern.regex.finditer(line_content):
                    secret = match.group()
                    entropy = self.calculate_entropy(secret)
                    
                    matches.append(GitHubSecretMatch(
                        pattern_name=pattern.name,
                        secret_value=secret,
                        file_path=file_path,
                        repo_name=repo_name,
                        branch=branch,
                        commit_sha=commit_sha,
                        commit_message=commit_message,
                        commit_date=commit_date,
                        author=author,
                        line_number=0,  # Line number not available in diff
                        severity=pattern.severity,
                        url=url,
                        entropy_score=entropy
                    ))
        
        return matches
    
    async def scan_repository(
        self,
        owner: str,
        repo: str,
        branch: str = 'main',
        max_commits: int = 100,
        scan_files: bool = True,
        scan_commits: bool = True
    ) -> AsyncGenerator[GitHubSecretMatch, None]:
        """
        Scan entire repository for secrets
        
        Args:
            owner: Repository owner
            repo: Repository name
            branch: Branch to scan
            max_commits: Maximum commits to scan
            scan_files: Scan current files in the repository
            scan_commits: Scan commit history
            
        Yields:
            GitHubSecretMatch objects for each found secret
        """
        logger.info(f"Scanning {owner}/{repo} branch: {branch}")
        
        # Get repository info
        repo_info = await self.api.get_repo_info(owner, repo)
        if not repo_info:
            logger.error(f"Repository {owner}/{repo} not found")
            return
        
        repo_name = f"{owner}/{repo}"
        repo_url = repo_info.get('html_url', f"https://github.com/{owner}/{repo}")
        
        # Scan current files if requested
        if scan_files:
            async for match in self._scan_current_files(owner, repo, branch, repo_name, repo_url):
                self.stats['files_scanned'] += 1
                yield match
        
        # Scan commit history if requested
        if scan_commits:
            async for match in self._scan_commit_history(
                owner, repo, branch, max_commits, repo_name, repo_url
            ):
                self.stats['commits_scanned'] += 1
                yield match
        
        logger.info(f"Scan complete. Stats: {self.stats}")
    
    async def _scan_current_files(
        self,
        owner: str,
        repo: str,
        branch: str,
        repo_name: str,
        repo_url: str
    ) -> AsyncGenerator[GitHubSecretMatch, None]:
        """Scan current files in the repository"""
        # Get repository tree
        tree = await self.api.get_tree(owner, repo, branch, recursive=True)
        
        for item in tree:
            if item['type'] != 'blob':
                continue
            
            file_path = item['path']
            
            # Skip large files
            if item.get('size', 0) > self.max_file_size:
                logger.debug(f"Skipping large file: {file_path}")
                continue
            
            # Check if this is a sensitive file
            is_sensitive = GitHubPatternDatabase.is_sensitive_file(file_path)
            
            # Get file content
            content = await self.api.get_file_content(owner, repo, file_path, branch)
            if not content:
                continue
            
            # Scan content
            matches = self.scan_content(
                content=content,
                file_path=file_path,
                repo_name=repo_name,
                branch=branch,
                commit_sha='HEAD',
                commit_message='Current file',
                commit_date=datetime.now(timezone.utc).isoformat(),
                author='',
                url=f"{repo_url}/blob/{branch}/{file_path}"
            )
            
            for match in matches:
                # Boost severity for sensitive files
                if is_sensitive and match.severity == SecretSeverity.MEDIUM:
                    match.severity = SecretSeverity.HIGH
                elif is_sensitive and match.severity == SecretSeverity.HIGH:
                    match.severity = SecretSeverity.CRITICAL
                
                yield match
            
            # Small delay to prevent overwhelming
            await asyncio.sleep(0.01)
    
    async def _scan_commit_history(
        self,
        owner: str,
        repo: str,
        branch: str,
        max_commits: int,
        repo_name: str,
        repo_url: str
    ) -> AsyncGenerator[GitHubSecretMatch, None]:
        """Scan commit history for secrets"""
        # Get commits
        commits = await self.api.get_commits(owner, repo, branch, max_commits=max_commits)
        
        for commit in commits:
            commit_sha = commit['sha']
            
            # Skip if already processed
            if commit_sha in self.processed_commits:
                continue
            
            self.processed_commits.add(commit_sha)
            
            # Extract commit info
            commit_info = commit.get('commit', {})
            commit_message = commit_info.get('message', '')
            commit_date = commit_info.get('author', {}).get('date', '')
            author = commit_info.get('author', {}).get('name', '')
            
            # Check commit message for secrets
            message_matches = GitHubPatternDatabase.check_commit_message(commit_message)
            for secret, severity in message_matches:
                yield GitHubSecretMatch(
                    pattern_name="Commit Message Secret",
                    secret_value=secret,
                    file_path="COMMIT_MESSAGE",
                    repo_name=repo_name,
                    branch=branch,
                    commit_sha=commit_sha,
                    commit_message=commit_message,
                    commit_date=commit_date,
                    author=author,
                    line_number=0,
                    severity=severity,
                    url=f"{repo_url}/commit/{commit_sha}"
                )
            
            # Get commit details with diff
            commit_details = await self.api.get_commit_details(owner, repo, commit_sha)
            if commit_details and commit_details.get('diff'):
                self.stats['diffs_analyzed'] += 1
                
                # Scan diff
                diff_matches = self.scan_diff(
                    diff=commit_details['diff'],
                    repo_name=repo_name,
                    branch=branch,
                    commit_sha=commit_sha,
                    commit_message=commit_message,
                    commit_date=commit_date,
                    author=author,
                    url=f"{repo_url}/commit/{commit_sha}"
                )
                
                for match in diff_matches:
                    yield match
            
            # Small delay
            await asyncio.sleep(0.05)

# ============================================================================
# Utility Functions
# ============================================================================

def parse_github_url(url: str) -> Tuple[str, str, str]:
    """
    Parse GitHub URL to extract owner, repo, and branch
    
    Examples:
    - https://github.com/owner/repo
    - https://github.com/owner/repo/tree/branch
    - https://github.com/owner/repo.git
    """
    # Remove .git suffix
    url = url.rstrip('.git')
    
    # Parse URL
    parsed = urlparse(url)
    
    if 'github.com' not in parsed.netloc:
        raise ValueError("Not a GitHub URL")
    
    # Split path
    parts = parsed.path.strip('/').split('/')
    
    if len(parts) < 2:
        raise ValueError("Invalid GitHub URL format")
    
    owner = parts[0]
    repo = parts[1]
    branch = 'main'  # Default
    
    # Check for branch in URL
    if len(parts) >= 4 and parts[2] == 'tree':
        branch = parts[3]
    
    return owner, repo, branch

# ============================================================================
# Main Entry Point (for testing)
# ============================================================================

async def main():
    """Test the GitHub scanner"""
    import argparse
    import math  # Import math for entropy calculation
    
    parser = argparse.ArgumentParser(description='Test GitHub Scanner')
    parser.add_argument('--token', required=True, help='GitHub token')
    parser.add_argument('--repo', required=True, help='GitHub repo URL')
    parser.add_argument('--branch', default='main', help='Branch to scan')
    parser.add_argument('--commits', type=int, default=50, help='Max commits')
    parser.add_argument('--no-files', action='store_true', help='Skip file scanning')
    parser.add_argument('--no-commits', action='store_true', help='Skip commit scanning')
    
    args = parser.parse_args()
    
    # Parse repo URL
    try:
        owner, repo, branch = parse_github_url(args.repo)
        branch = args.branch or branch
    except ValueError as e:
        print(f"Error: {e}")
        return
    
    # Create client and scanner
    async with GitHubAPIClient(args.token) as client:
        scanner = GitHubScanner(client)
        
        # Add a simple test pattern
        from secret_detector import Pattern, SecretSeverity
        scanner.set_patterns([
            Pattern(
                name="Test Pattern",
                regex=re.compile(r'secret|token|key|password', re.I),
                severity=SecretSeverity.HIGH,
                keywords=[]
            )
        ])
        
        # Scan repository
        print(f"Scanning {owner}/{repo}...")
        async for match in scanner.scan_repository(
            owner, repo, branch,
            max_commits=args.commits,
            scan_files=not args.no_files,
            scan_commits=not args.no_commits
        ):
            print(f"Found: {match.pattern_name} in {match.file_path}")
            print(f"  Commit: {match.commit_sha[:8]} - {match.commit_message[:50]}")
            print(f"  Severity: {match.severity.value}")
            print()

if __name__ == "__main__":
    asyncio.run(main())
    