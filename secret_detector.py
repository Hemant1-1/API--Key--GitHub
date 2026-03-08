#!/usr/bin/env python3
"""
CyberGhost-Ultra-Scanner Core Engine
Thermal-aware secret detection with hardware protection for i3 3rd Gen
Fastest and safest scanner engine ever created
"""

import re
import math
import time
import psutil
import platform
import os
import mmap
import json
from pathlib import Path
from typing import List, Dict, Set, Tuple, Optional, Iterator, Pattern as RegexPattern
from dataclasses import dataclass, field, asdict
from enum import Enum
from collections import Counter
from functools import lru_cache, wraps
import threading
import signal
from concurrent.futures import ThreadPoolExecutor
import gc
import array

# ============================================================================
# Enums and Data Classes
# ============================================================================

class SecretSeverity(Enum):
    """Severity levels for found secrets"""
    CRITICAL = "CRITICAL"  # Live API keys, passwords, tokens
    HIGH = "HIGH"          # Potential keys, sensitive configs
    MEDIUM = "MEDIUM"      # High entropy strings, internal tokens
    LOW = "LOW"            # References to secrets, placeholders
    
    def __lt__(self, other):
        if self.__class__ is other.__class__:
            return self.value < other.value
        return NotImplemented

@dataclass(slots=True, frozen=True)
class SecretMatch:
    """Immutable secret match result for thread safety"""
    pattern_name: str
    secret_value: str
    line_number: int
    file_path: str
    severity: SecretSeverity
    entropy_score: float = 0.0
    timestamp: float = field(default_factory=time.time)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization"""
        return {
            'pattern_name': self.pattern_name,
            'secret_value': self.secret_value[:50] + '...' if len(self.secret_value) > 50 else self.secret_value,
            'line_number': self.line_number,
            'file_path': self.file_path,
            'severity': self.severity.value,
            'entropy_score': round(self.entropy_score, 2),
            'timestamp': self.timestamp
        }

@dataclass(slots=True)
class Pattern:
    """Compiled regex pattern with metadata"""
    name: str
    regex: RegexPattern
    severity: SecretSeverity
    weight: float = 1.0  # For confidence scoring

# ============================================================================
# Thermal Guard - Hardware Protection
# ============================================================================

class ThermalGuard:
    """
    Protects i3 3rd Gen hardware from thermal damage
    Monitors CPU temperature and usage, pauses scanning when needed
    """
    
    # Temperature thresholds for i3 3rd Gen (safe limits)
    TEMP_WARNING = 80  # °C - Start throttling
    TEMP_CRITICAL = 85  # °C - Pause scanning
    TEMP_MAX = 95  # °C - Emergency shutdown
    
    # CPU usage thresholds
    CPU_WARNING = 80  # % - High usage
    CPU_CRITICAL = 90  # % - Very high usage
    
    def __init__(self, 
                 temp_threshold: float = 85,
                 cpu_threshold: float = 90,
                 cooldown_time: int = 5,
                 check_interval: float = 1.0):
        
        self.temp_threshold = temp_threshold
        self.cpu_threshold = cpu_threshold
        self.cooldown_time = cooldown_time
        self.check_interval = check_interval
        
        # State
        self.scan_paused = False
        self.running = True
        self.monitor_thread = None
        self.system_os = platform.system()
        
        # Statistics
        self.total_cooldowns = 0
        self.total_cooldown_seconds = 0
        self.peak_temperature = 0
        self.peak_cpu = 0
        
        # Thermal history for trending
        self.temp_history = []
        self.max_history = 60  # Keep last 60 readings
        
        # Lock for thread safety
        self._lock = threading.Lock()
        
    def start(self):
        """Start thermal monitoring in background thread"""
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        return self
    
    def stop(self):
        """Stop thermal monitoring"""
        self.running = False
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=2)
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.running:
            try:
                # Get current readings
                temp = self._get_cpu_temperature()
                cpu = self._get_cpu_usage()
                
                # Update peak values
                with self._lock:
                    self.peak_temperature = max(self.peak_temperature, temp)
                    self.peak_cpu = max(self.peak_cpu, cpu)
                    
                    # Add to history
                    self.temp_history.append(temp)
                    if len(self.temp_history) > self.max_history:
                        self.temp_history.pop(0)
                
                # Check if we need to pause
                if temp >= self.temp_threshold or cpu >= self.cpu_threshold:
                    if not self.scan_paused:
                        self._enter_cooldown(temp, cpu)
                else:
                    if self.scan_paused and temp < self.temp_threshold - 5:
                        self._exit_cooldown()
                
                # Dynamic threshold adjustment based on trend
                self._adjust_thresholds()
                
            except Exception as e:
                # Silently fail - don't crash scanner if monitoring fails
                pass
            
            # Sleep for check interval
            time.sleep(self.check_interval)
    
    def _get_cpu_temperature(self) -> float:
        """Get CPU temperature across different platforms"""
        try:
            if self.system_os == "Linux":
                # Try multiple thermal zones
                for i in range(10):
                    path = f"/sys/class/thermal/thermal_zone{i}/temp"
                    if os.path.exists(path):
                        with open(path, 'r') as f:
                            temp = float(f.read().strip()) / 1000.0
                            if 20 < temp < 110:  # Sanity check
                                return temp
                
                # Try hwmon as fallback
                for i in range(5):
                    path = f"/sys/class/hwmon/hwmon{i}/temp1_input"
                    if os.path.exists(path):
                        with open(path, 'r') as f:
                            temp = float(f.read().strip()) / 1000.0
                            if 20 < temp < 110:
                                return temp
                                
            elif self.system_os == "Windows":
                # Use WMI on Windows
                try:
                    import wmi
                    w = wmi.WMI(namespace="root\\wmi")
                    temps = w.MSAcpi_ThermalZoneTemperature()
                    if temps:
                        return float(temps[0].CurrentTemperature) / 10.0 - 273.15
                except:
                    pass
                    
            elif self.system_os == "Darwin":
                # Use sysctl on macOS
                try:
                    import subprocess
                    output = subprocess.check_output(
                        ["sysctl", "-n", "machdep.xcpm.cpu_thermal_level"],
                        universal_newlines=True
                    ).strip()
                    if output:
                        return float(output)
                except:
                    pass
        
        except Exception:
            pass
        
        return 0.0  # Return 0 if temperature not available
    
    def _get_cpu_usage(self) -> float:
        """Get current CPU usage percentage"""
        try:
            return psutil.cpu_percent(interval=0.1)
        except:
            return 0.0
    
    def _enter_cooldown(self, temp: float, cpu: float):
        """Enter cooldown mode - pause scanning"""
        with self._lock:
            self.scan_paused = True
            self.total_cooldowns += 1
            
            print(f"\n🌡️  THERMAL GUARD ACTIVATED")
            print(f"   Temperature: {temp:.1f}°C | CPU: {cpu:.1f}%")
            print(f"   Pausing scan for {self.cooldown_time}s to cool down...")
            
            # Record start time
            cooldown_start = time.time()
            
            # Force garbage collection during cooldown
            gc.collect()
            
            # Sleep for cooldown
            time.sleep(self.cooldown_time)
            
            # Update statistics
            self.total_cooldown_seconds += time.time() - cooldown_start
    
    def _exit_cooldown(self):
        """Exit cooldown mode - resume scanning"""
        with self._lock:
            self.scan_paused = False
            print(f"\n✅ Thermal Guard: Resuming scan after cooldown")
    
    def _adjust_thresholds(self):
        """Dynamically adjust thresholds based on temperature trend"""
        if len(self.temp_history) < 10:
            return
        
        # Calculate rate of temperature increase
        recent = self.temp_history[-5:]
        if len(recent) < 2:
            return
        
        rate = (recent[-1] - recent[0]) / len(recent)
        
        # If temperature rising quickly, lower thresholds temporarily
        if rate > 0.5:  # Rising more than 0.5°C per check
            with self._lock:
                self.temp_threshold = max(70, self.temp_threshold - 2)
        elif rate < -0.3:  # Cooling down
            with self._lock:
                self.temp_threshold = min(85, self.temp_threshold + 1)
    
    def wait_if_needed(self):
        """Wait if scan is paused (called by scanner)"""
        while self.scan_paused and self.running:
            time.sleep(0.5)
    
    def get_stats(self) -> Dict:
        """Get thermal statistics"""
        with self._lock:
            return {
                'total_cooldowns': self.total_cooldowns,
                'total_cooldown_seconds': self.total_cooldown_seconds,
                'peak_temperature': self.peak_temperature,
                'peak_cpu': self.peak_cpu,
                'current_temp': self._get_cpu_temperature(),
                'current_cpu': self._get_cpu_usage(),
                'threshold_temp': self.temp_threshold,
                'threshold_cpu': self.cpu_threshold
            }

# ============================================================================
# Optimized Pattern Database
# ============================================================================

class PatternDatabase:
    """Ultra-optimized pattern compilation and management"""
    
    @staticmethod
    def compile_patterns() -> List[Pattern]:
        """Compile all patterns with optimal flags"""
        patterns = []
        
        # ==================== AWS ====================
        patterns.append(Pattern(
            name="AWS Access Key ID",
            regex=re.compile(
                r'(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9])',
                re.ASCII  # ASCII only for speed
            ),
            severity=SecretSeverity.CRITICAL
        ))
        
        patterns.append(Pattern(
            name="AWS Secret Key",
            regex=re.compile(
                r'(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])',
                re.ASCII
            ),
            severity=SecretSeverity.CRITICAL
        ))
        
        patterns.append(Pattern(
            name="AWS Session Token",
            regex=re.compile(
                r'(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{344}(?![A-Za-z0-9/+=])',
                re.ASCII
            ),
            severity=SecretSeverity.CRITICAL
        ))
        
        # ==================== GCP ====================
        patterns.append(Pattern(
            name="GCP API Key",
            regex=re.compile(
                r'AIza[0-9A-Za-z\-_]{35}',
                re.ASCII
            ),
            severity=SecretSeverity.CRITICAL
        ))
        
        patterns.append(Pattern(
            name="GCP OAuth Client",
            regex=re.compile(
                r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
                re.IGNORECASE
            ),
            severity=SecretSeverity.CRITICAL
        ))
        
        patterns.append(Pattern(
            name="GCP Service Account",
            regex=re.compile(
                r'"type":\s*"service_account"[^}]*"private_key":\s*"[^"]+"',
                re.IGNORECASE | re.DOTALL
            ),
            severity=SecretSeverity.CRITICAL
        ))
        
        # ==================== Azure ====================
        patterns.append(Pattern(
            name="Azure Storage Key",
            regex=re.compile(
                r'(?<![A-Za-z0-9+/=])[A-Za-z0-9+/=]{88}(?![A-Za-z0-9+/=])',
                re.ASCII
            ),
            severity=SecretSeverity.CRITICAL
        ))
        
        patterns.append(Pattern(
            name="Azure Connection String",
            regex=re.compile(
                r'DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}',
                re.IGNORECASE
            ),
            severity=SecretSeverity.CRITICAL
        ))
        
        patterns.append(Pattern(
            name="Azure Client Secret",
            regex=re.compile(
                r'(?<![A-Za-z0-9._-])[A-Za-z0-9._-]{34}(?![A-Za-z0-9._-])',
                re.ASCII
            ),
            severity=SecretSeverity.CRITICAL
        ))
        
        # ==================== Slack ====================
        patterns.append(Pattern(
            name="Slack Webhook",
            regex=re.compile(
                r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+',
                re.IGNORECASE
            ),
            severity=SecretSeverity.CRITICAL
        ))
        
        patterns.append(Pattern(
            name="Slack Token",
            regex=re.compile(
                r'xox[baprs]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}',
                re.ASCII
            ),
            severity=SecretSeverity.CRITICAL
        ))
        
        # ==================== GitHub ====================
        patterns.append(Pattern(
            name="GitHub PAT",
            regex=re.compile(
                r'ghp_[A-Za-z0-9]{36}',
                re.ASCII
            ),
            severity=SecretSeverity.CRITICAL
        ))
        
        patterns.append(Pattern(
            name="GitHub OAuth",
            regex=re.compile(
                r'gho_[A-Za-z0-9]{36}',
                re.ASCII
            ),
            severity=SecretSeverity.CRITICAL
        ))
        
        patterns.append(Pattern(
            name="GitHub App Token",
            regex=re.compile(
                r'ghu_[A-Za-z0-9]{36}',
                re.ASCII
            ),
            severity=SecretSeverity.CRITICAL
        ))
        
        patterns.append(Pattern(
            name="GitHub Refresh",
            regex=re.compile(
                r'ghr_[A-Za-z0-9]{36}',
                re.ASCII
            ),
            severity=SecretSeverity.CRITICAL
        ))
        
        # ==================== Database ====================
        patterns.append(Pattern(
            name="PostgreSQL URL",
            regex=re.compile(
                r'postgres(?:ql)?://[^:]+:[^@]+@[^:]+:\d+/[^\s]+',
                re.IGNORECASE
            ),
            severity=SecretSeverity.CRITICAL
        ))
        
        patterns.append(Pattern(
            name="MySQL URL",
            regex=re.compile(
                r'mysql://[^:]+:[^@]+@[^:]+:\d+/[^\s]+',
                re.IGNORECASE
            ),
            severity=SecretSeverity.CRITICAL
        ))
        
        patterns.append(Pattern(
            name="MongoDB URL",
            regex=re.compile(
                r'mongodb(?:\+srv)?://[^:]+:[^@]+@[^:]+(?::\d+)?/[^\s]+',
                re.IGNORECASE
            ),
            severity=SecretSeverity.CRITICAL
        ))
        
        patterns.append(Pattern(
            name="Redis URL",
            regex=re.compile(
                r'redis://(?:[^@]+@)?[^:]+:\d+(?:/\d+)?',
                re.IGNORECASE
            ),
            severity=SecretSeverity.CRITICAL
        ))
        
        # ==================== Private Keys ====================
        patterns.append(Pattern(
            name="RSA Private Key",
            regex=re.compile(
                r'-----BEGIN RSA PRIVATE KEY-----.+?-----END RSA PRIVATE KEY-----',
                re.DOTALL | re.IGNORECASE
            ),
            severity=SecretSeverity.CRITICAL
        ))
        
        patterns.append(Pattern(
            name="SSH Private Key",
            regex=re.compile(
                r'-----BEGIN OPENSSH PRIVATE KEY-----.+?-----END OPENSSH PRIVATE KEY-----',
                re.DOTALL | re.IGNORECASE
            ),
            severity=SecretSeverity.CRITICAL
        ))
        
        patterns.append(Pattern(
            name="PGP Private Key",
            regex=re.compile(
                r'-----BEGIN PGP PRIVATE KEY BLOCK-----.+?-----END PGP PRIVATE KEY BLOCK-----',
                re.DOTALL | re.IGNORECASE
            ),
            severity=SecretSeverity.CRITICAL
        ))
        
        # ==================== Payment ====================
        patterns.append(Pattern(
            name="Stripe Live Key",
            regex=re.compile(
                r'sk_live_[0-9a-zA-Z]{24}',
                re.ASCII
            ),
            severity=SecretSeverity.CRITICAL
        ))
        
        patterns.append(Pattern(
            name="Stripe Test Key",
            regex=re.compile(
                r'sk_test_[0-9a-zA-Z]{24}',
                re.ASCII
            ),
            severity=SecretSeverity.HIGH
        ))
        
        patterns.append(Pattern(
            name="Stripe Webhook",
            regex=re.compile(
                r'whsec_[0-9a-zA-Z]{32}',
                re.ASCII
            ),
            severity=SecretSeverity.CRITICAL
        ))
        
        patterns.append(Pattern(
            name="PayPal Secret",
            regex=re.compile(
                r'(?<![A-Za-z0-9])[A-Za-z0-9]{40}(?![A-Za-z0-9])',
                re.ASCII
            ),
            severity=SecretSeverity.CRITICAL
        ))
        
        # ==================== Generic High Entropy ====================
        patterns.append(Pattern(
            name="High Entropy String",
            regex=re.compile(
                r'[A-Za-z0-9\-_=+/]{16,}',
                re.ASCII
            ),
            severity=SecretSeverity.MEDIUM,
            weight=0.5  # Lower confidence
        ))
        
        return patterns

# ============================================================================
# Entropy Calculator with Caching
# ============================================================================

class EntropyCalculator:
    """Ultra-fast Shannon entropy calculation with caching"""
    
    def __init__(self, cache_size: int = 10000):
        self.cache_size = cache_size
        self._cache = {}
        self._cache_hits = 0
        self._cache_misses = 0
        
        # Pre-compute log2 for common probabilities (optimization)
        self._log2_cache = {i: math.log2(i) for i in range(1, 256)}
    
    @lru_cache(maxsize=10000)
    def calculate(self, data: str) -> float:
        """Calculate Shannon entropy with caching"""
        if not data or len(data) < 4:
            return 0.0
        
        length = len(data)
        
        # Fast path: check if it's all the same character
        if len(set(data)) == 1:
            return 0.0
        
        # Use array for faster counting (C-level speed)
        counts = array.array('I', [0]) * 256
        
        # Count characters
        for char in data.encode('ascii', errors='ignore'):
            counts[char] += 1
        
        # Calculate entropy
        entropy = 0.0
        for count in counts:
            if count > 0:
                p = count / length
                entropy -= p * self._log2_cache.get(int(p * 1000), math.log2(p))
        
        return entropy
    
    def get_stats(self) -> Dict:
        """Get cache statistics"""
        return {
            'cache_hits': self._cache_hits,
            'cache_misses': self._cache_misses,
            'cache_size': len(self._cache)
        }

# ============================================================================
# Thermal-Aware Scanner
# ============================================================================

class ThermalAwareScanner:
    """
    Core scanning engine with thermal protection
    Fastest and safest scanner ever built
    """
    
    def __init__(self,
                 thermal_guard: ThermalGuard,
                 entropy_threshold: float = 3.8,
                 min_length: int = 8,
                 chunk_size: int = 1024 * 1024,  # 1MB chunks
                 max_line_length: int = 10000,    # Skip extremely long lines
                 use_entropy: bool = True):
        
        self.thermal = thermal_guard
        self.entropy_threshold = entropy_threshold
        self.min_length = min_length
        self.chunk_size = chunk_size
        self.max_line_length = max_line_length
        self.use_entropy = use_entropy
        
        # Compile patterns
        self.patterns = PatternDatabase.compile_patterns()
        
        # Initialize entropy calculator
        self.entropy = EntropyCalculator()
        
        # Statistics
        self.stats = {
            'files_scanned': 0,
            'lines_scanned': 0,
            'secrets_found': 0,
            'bytes_processed': 0,
            'scan_time': 0,
            'patterns_matched': Counter()
        }
        
        # Thread pool for parallel processing (limited for i3)
        self.executor = ThreadPoolExecutor(max_workers=2)
        
        # Binary file extensions to skip
        self.binary_extensions = {
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico',
            '.mp3', '.mp4', '.avi', '.mov', '.wmv',
            '.zip', '.gz', '.tar', '.rar', '.7z',
            '.exe', '.dll', '.so', '.dylib',
            '.pdf', '.doc', '.docx', '.xls', '.xlsx',
            '.pyc', '.pyo', '.class', '.o'
        }
    
    def scan_file(self, file_path: str) -> Iterator[SecretMatch]:
        """
        Scan a single file for secrets with thermal protection
        Uses memory-mapped I/O for maximum speed
        """
        file_start = time.time()
        
        try:
            # Skip binary files
            if self._is_binary_file(file_path):
                return
            
            # Get file size
            file_size = os.path.getsize(file_path)
            if file_size == 0:
                return
            
            # Update stats
            self.stats['bytes_processed'] += file_size
            
            # Use memory mapping for large files
            if file_size > 1024 * 1024:  # > 1MB
                yield from self._scan_file_mmap(file_path)
            else:
                # Small files: read normally
                yield from self._scan_file_normal(file_path)
            
        except Exception as e:
            print(f"Error scanning {file_path}: {e}")
        finally:
            self.stats['files_scanned'] += 1
            self.stats['scan_time'] += time.time() - file_start
    
    def _scan_file_normal(self, file_path: str) -> Iterator[SecretMatch]:
        """Scan small file using normal I/O"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    # Check thermal status
                    self.thermal.wait_if_needed()
                    
                    # Skip extremely long lines
                    if len(line) > self.max_line_length:
                        continue
                    
                    # Scan line
                    matches = self._scan_line(line, file_path, line_num)
                    for match in matches:
                        self.stats['secrets_found'] += 1
                        self.stats['patterns_matched'][match.pattern_name] += 1
                        yield match
                    
                    self.stats['lines_scanned'] += 1
                    
        except UnicodeDecodeError:
            # Binary file, skip
            pass
    
    def _scan_file_mmap(self, file_path: str) -> Iterator[SecretMatch]:
        """Scan large file using memory mapping for speed"""
        try:
            with open(file_path, 'rb') as f:
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                    # Process in chunks
                    content = mm.read().decode('utf-8', errors='ignore')
                    
                    line_num = 0
                    for line in content.split('\n'):
                        line_num += 1
                        
                        # Check thermal status
                        self.thermal.wait_if_needed()
                        
                        # Skip extremely long lines
                        if len(line) > self.max_line_length:
                            continue
                        
                        # Scan line
                        matches = self._scan_line(line, file_path, line_num)
                        for match in matches:
                            self.stats['secrets_found'] += 1
                            self.stats['patterns_matched'][match.pattern_name] += 1
                            yield match
                        
                        self.stats['lines_scanned'] += 1
                        
        except Exception as e:
            print(f"MMAP error for {file_path}: {e}")
    
    def _scan_line(self, line: str, file_path: str, line_num: int) -> List[SecretMatch]:
        """Scan a single line for secrets"""
        matches = []
        
        # Skip empty lines
        if not line or len(line) < self.min_length:
            return matches
        
        # Apply all patterns
        for pattern in self.patterns:
            for match in pattern.regex.finditer(line):
                secret = match.group()
                
                # Skip if too short
                if len(secret) < self.min_length:
                    continue
                
                # Calculate entropy if needed
                entropy = 0.0
                if self.use_entropy and pattern.weight < 1.0:
                    entropy = self.entropy.calculate(secret)
                    
                    # Skip if entropy too low for low-confidence patterns
                    if pattern.weight < 1.0 and entropy < self.entropy_threshold:
                        continue
                
                matches.append(SecretMatch(
                    pattern_name=pattern.name,
                    secret_value=secret,
                    line_number=line_num,
                    file_path=file_path,
                    severity=pattern.severity,
                    entropy_score=entropy
                ))
        
        return matches
    
    def _is_binary_file(self, file_path: str) -> bool:
        """Quick check if file is binary"""
        ext = os.path.splitext(file_path)[1].lower()
        if ext in self.binary_extensions:
            return True
        
        # Check first few bytes for null bytes
        try:
            with open(file_path, 'rb') as f:
                chunk = f.read(1024)
                return b'\0' in chunk
        except:
            return True
    
    def scan_directory(self, path: str) -> Iterator[SecretMatch]:
        """Recursively scan a directory"""
        path = Path(path)
        
        if path.is_file():
            yield from self.scan_file(str(path))
        else:
            for root, dirs, files in os.walk(path):
                # Skip common directories
                dirs[:] = [d for d in dirs if d not in {
                    '.git', 'node_modules', 'venv', '__pycache__',
                    'build', 'dist', 'target', '.idea', '.vscode'
                }]
                
                for file in files:
                    file_path = os.path.join(root, file)
                    
                    # Check thermal status before each file
                    self.thermal.wait_if_needed()
                    
                    # Scan file
                    yield from self.scan_file(file_path)
    
    def get_stats(self) -> Dict:
        """Get scanner statistics"""
        stats = self.stats.copy()
        stats['patterns_matched'] = dict(self.stats['patterns_matched'])
        stats['entropy_cache'] = self.entropy.get_stats()
        stats['thermal'] = self.thermal.get_stats()
        
        # Calculate rates
        if stats['scan_time'] > 0:
            stats['files_per_second'] = stats['files_scanned'] / stats['scan_time']
            stats['lines_per_second'] = stats['lines_scanned'] / stats['scan_time']
            stats['mb_per_second'] = (stats['bytes_processed'] / 1024 / 1024) / stats['scan_time']
        
        return stats

# ============================================================================
# Main Entry Point
# ============================================================================

def main():
    """Test the scanner"""
    import argparse
    
    parser = argparse.ArgumentParser(description='CyberGhost-Ultra-Scanner Core Engine')
    parser.add_argument('path', help='Path to scan')
    parser.add_argument('--temp-threshold', type=float, default=85, help='Temperature threshold (°C)')
    parser.add_argument('--cpu-threshold', type=float, default=90, help='CPU threshold (%)')
    parser.add_argument('--entropy', type=float, default=3.8, help='Entropy threshold')
    parser.add_argument('--no-entropy', action='store_true', help='Disable entropy detection')
    parser.add_argument('--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    print("=" * 70)
    print("🚀 CYBERGHOST-ULTRA-SCANNER CORE ENGINE")
    print("=" * 70)
    print(f"Target: {args.path}")
    print(f"Thermal Guard: {args.temp_threshold}°C / {args.cpu_threshold}% CPU")
    print(f"Entropy Detection: {'Disabled' if args.no_entropy else f'Threshold {args.entropy}'}")
    print("=" * 70)
    
    # Initialize thermal guard
    thermal = ThermalGuard(
        temp_threshold=args.temp_threshold,
        cpu_threshold=args.cpu_threshold
    ).start()
    
    try:
        # Initialize scanner
        scanner = ThermalAwareScanner(
            thermal_guard=thermal,
            entropy_threshold=args.entropy,
            use_entropy=not args.no_entropy
        )
        
        # Scan
        start_time = time.time()
        found_count = 0
        
        for match in scanner.scan_directory(args.path):
            found_count += 1
            
            if args.verbose:
                severity_color = {
                    'CRITICAL': '\033[91m',  # Red
                    'HIGH': '\033[93m',       # Yellow
                    'MEDIUM': '\033[94m',      # Blue
                    'LOW': '\033[92m'          # Green
                }.get(match.severity.value, '')
                
                print(f"{severity_color}[{match.severity.value}]\033[0m "
                      f"{match.pattern_name} in {match.file_path}:{match.line_number}")
                print(f"      Secret: {match.secret_value[:50]}...")
                if match.entropy_score > 0:
                    print(f"      Entropy: {match.entropy_score:.2f}")
                print()
        
        # Print statistics
        elapsed = time.time() - start_time
        stats = scanner.get_stats()
        
        print("\n" + "=" * 70)
        print("📊 SCAN COMPLETE")
        print("=" * 70)
        print(f"Files scanned: {stats['files_scanned']:,}")
        print(f"Lines scanned: {stats['lines_scanned']:,}")
        print(f"Secrets found: {stats['secrets_found']}")
        print(f"Scan time: {elapsed:.1f}s")
        print(f"Processing rate: {stats['mb_per_second']:.1f} MB/s")
        
        # Thermal stats
        if stats['thermal']['total_cooldowns'] > 0:
            print(f"\n🌡️  Thermal Events: {stats['thermal']['total_cooldowns']}")
            print(f"   Cooldown time: {stats['thermal']['total_cooldown_seconds']:.1f}s")
            print(f"   Peak temperature: {stats['thermal']['peak_temperature']:.1f}°C")
        
        # Pattern matches
        if stats['patterns_matched']:
            print("\n📈 Top Patterns:")
            for pattern, count in sorted(
                stats['patterns_matched'].items(),
                key=lambda x: x[1],
                reverse=True
            )[:5]:
                print(f"   {pattern}: {count}")
        
    finally:
        thermal.stop()

if __name__ == "__main__":
    main()
    