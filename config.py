"""
Configuration management for CyberGhost-Ultra-Scanner
"""

import os
from pathlib import Path
from dataclasses import dataclass
import json
import multiprocessing

@dataclass
class Config:
    # GitHub API settings
    GITHUB_API_BASE = "https://api.github.com"
    GITHUB_GRAPHQL_URL = "https://api.github.com/graphql"
    REQUEST_TIMEOUT = 30
    MAX_RETRIES = 3
    RETRY_DELAY = 1
    
    # Performance settings
    MAX_CONCURRENT_REQUESTS = 50  # aiohttp limit
    MAX_CONCURRENT_REPOS = 5  # Concurrent repository scans
    CHUNK_SIZE = 100  # Items per page for pagination
    RATE_LIMIT_SLEEP = 60  # Seconds to sleep when rate limited
    
    # Multiprocessing settings
    CPU_COUNT = multiprocessing.cpu_count()
    WORKER_PROCESSES = max(1, CPU_COUNT - 1)  # Leave one CPU free
    
    # Memory management
    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB max file size
    BATCH_SIZE = 1000  # Process secrets in batches for verification
    
    # Paths
    BASE_DIR = Path(__file__).parent
    REPORT_DIR = BASE_DIR / "reports"
    CACHE_DIR = BASE_DIR / "cache"
    
    # Entropy detection
    ENTROPY_THRESHOLD = 4.5  # Minimum Shannon entropy for random strings
    MIN_SECRET_LENGTH = 16  # Minimum length for entropy-based detection
    
    # Regex patterns for secret detection
    SECRET_PATTERNS = {
        'aws_access_key': r'AKIA[0-9A-Z]{16}',
        'aws_secret_key': r'(?i)aws(.{0,20})?secret[a-zA-Z0-9/\+=]{40}',
        'google_api_key': r'AIza[0-9A-Za-z\-_]{35}',
        'google_oauth': r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
        'stripe_live_key': r'(?:sk|pk)_live_[0-9a-zA-Z]{24,}',
        'stripe_test_key': r'(?:sk|pk)_test_[0-9a-zA-Z]{24,}',
        'azure_connection_string': r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+',
        'slack_token': r'xox[baprs]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}',
        'github_token': r'gh[pousr]_[0-9a-zA-Z]{36,}',
        'private_key': r'-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
        'jwt_token': r'eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+',
        'mongodb_uri': r'mongodb(?:\+srv)?://[^/\s]+:[^/\s]+@',
        'postgresql_uri': r'postgresql://[^/\s]+:[^/\s]+@',
        'redis_uri': r'redis://[^/\s]+:[^/\s]+@',
        'docker_auth': r'{"auths":{[^}]+"auth":"[^"]+',
        'slack_webhook': r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+',
    }
    
    @classmethod
    def load_from_file(cls, config_path: str):
        """Load configuration from JSON file"""
        try:
            with open(config_path, 'r') as f:
                user_config = json.load(f)
                
            # Update attributes from user config
            for key, value in user_config.items():
                if hasattr(cls, key):
                    setattr(cls, key, value)
                    
        except Exception as e:
            print(f"Warning: Could not load config file: {e}")
    
    @classmethod
    def ensure_directories(cls):
        """Create necessary directories if they don't exist"""
        cls.REPORT_DIR.mkdir(exist_ok=True)
        cls.CACHE_DIR.mkdir(exist_ok=True)

# Create directories on module import
Config.ensure_directories()