#!/usr/bin/env python3
"""
World's #1 Secret Scanner - With Thermal Protection & Priority Control
Designed for i3 3rd Gen laptops - Prevents thermal throttling, runs indefinitely
"""

import os
import sys
import time
import math
import re
import argparse
import json
import psutil
import platform
import signal
from pathlib import Path
from typing import List, Dict, Set, Tuple, Optional, Generator
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
import threading
from concurrent.futures import ThreadPoolExecutor
import atexit

# ============================================================================
# Thermal & Process Management
# ============================================================================

class SystemProtection:
    """Manages CPU temperature, process priority, and system health"""
    
    def __init__(self, 
                 temp_threshold: float = 85.0,  # Celsius
                 usage_threshold: float = 90.0,  # Percentage
                 cooldown_time: int = 5,         # Seconds
                 check_interval: int = 2):       # Seconds between checks
        self.temp_threshold = temp_threshold
        self.usage_threshold = usage_threshold
        self.cooldown_time = cooldown_time
        self.check_interval = check_interval
        self.scan_paused = False
        self.total_cooldowns = 0
        self.total_cooldown_time = 0
        self.running = True
        self.monitor_thread = None
        self.current_process = None
        self.system_os = platform.system()
        
        # Set process priority on startup
        self._set_process_priority()
        
        # Register cleanup
        atexit.register(self.cleanup)
        
    def _set_process_priority(self):
        """Set process priority to Below Normal / Idle"""
        try:
            self.current_process = psutil.Process(os.getpid())
            
            if self.system_os == "Windows":
                # Windows priority classes
                # BELOW_NORMAL_PRIORITY_CLASS = 0x4000
                import ctypes
                kernel32 = ctypes.windll.kernel32
                kernel32.SetPriorityClass(
                    kernel32.GetCurrentProcess(), 
                    0x4000  # BELOW_NORMAL_PRIORITY_CLASS
                )
                print("✅ Process priority set to: Below Normal (Windows)")
                
            elif self.system_os == "Linux":
                # Linux nice value: 10 (below normal, range -20 to 19)
                os.nice(10)
                print(f"✅ Process priority set to: Nice value 10 (Linux)")
                
            elif self.system_os == "Darwin":  # macOS
                # macOS similar to Linux
                os.nice(5)
                print(f"✅ Process priority set to: Nice value 5 (macOS)")
            
            # Also set CPU affinity if possible (avoid first core)
            try:
                # Get available CPUs
                cpu_count = psutil.cpu_count()
                if cpu_count > 2:
                    # Use all except core 0 to keep system responsive
                    self.current_process.cpu_affinity(list(range(1, cpu_count)))
                    print(f"✅ CPU affinity set to cores: 1-{cpu_count-1}")
            except:
                pass  # CPU affinity not supported on all systems
                
        except Exception as e:
            print(f"⚠️  Could not set process priority: {e}")
    
    def get_cpu_temperature(self) -> float:
        """Get CPU temperature (platform specific)"""
        try:
            if self.system_os == "Linux":
                # Try multiple temperature sources on Linux
                temp_paths = [
                    "/sys/class/thermal/thermal_zone0/temp",
                    "/sys/class/hwmon/hwmon0/temp1_input",
                    "/sys/class/hwmon/hwmon1/temp1_input"
                ]
                
                for path in temp_paths:
                    if os.path.exists(path):
                        with open(path, 'r') as f:
                            temp = float(f.read().strip()) / 1000.0  # Usually millidegrees
                            return temp
                            
            elif self.system_os == "Windows":
                # Windows - use wmi if available
                try:
                    import wmi
                    w = wmi.WMI(namespace="root\\wmi")
                    temperature_info = w.MSAcpi_ThermalZoneTemperature()[0]
                    return float(temperature_info.CurrentTemperature) / 10.0 - 273.15  # Kelvin to Celsius
                except:
                    pass
                    
            elif self.system_os == "Darwin":
                # macOS - use osx-cpu-temp if available
                try:
                    import subprocess
                    output = subprocess.check_output(["osx-cpu-temp"], universal_newlines=True)
                    return float(output.split()[0])
                except:
                    pass
        
        except Exception as e:
            pass  # Silently fail, use CPU usage as fallback
        
        # Fallback: return 0 (will use CPU usage instead)
        return 0.0
    
    def get_cpu_usage(self) -> float:
        """Get current CPU usage percentage"""
        try:
            return self.current_process.cpu_percent(interval=0.1)
        except:
            return psutil.cpu_percent(interval=0.1)
    
    def monitor_system(self):
        """Background thread to monitor system health"""
        while self.running:
            try:
                # Check CPU usage
                cpu_usage = self.get_cpu_usage()
                
                # Check temperature (if available)
                cpu_temp = self.get_cpu_temperature()
                
                # Determine if we need to cool down
                need_cooldown = False
                reason = ""
                
                if cpu_temp > 0 and cpu_temp >= self.temp_threshold:
                    need_cooldown = True
                    reason = f"Temperature {cpu_temp:.1f}°C >= {self.temp_threshold}°C"
                elif cpu_usage >= self.usage_threshold:
                    need_cooldown = True
                    reason = f"CPU Usage {cpu_usage:.1f}% >= {self.usage_threshold}%"
                
                if need_cooldown and not self.scan_paused:
                    self.scan_paused = True
                    self.total_cooldowns += 1
                    print(f"\n🌡️  THERMAL PROTECTION: {reason}")
                    print(f"   Pausing scan for {self.cooldown_time} seconds...")
                    
                    # Actually pause
                    start_pause = time.time()
                    time.sleep(self.cooldown_time)
                    pause_duration = time.time() - start_pause
                    self.total_cooldown_time += pause_duration
                    
                    self.scan_paused = False
                    print(f"   Resuming scan after {pause_duration:.1f}s cooldown")
                    
                elif self.scan_paused and not need_cooldown:
                    self.scan_paused = False
                    
            except Exception as e:
                print(f"⚠️  Monitor error: {e}")
            
            # Check every interval
            for _ in range(int(self.check_interval * 2)):  # Check more frequently but sleep in small increments
                if not self.running:
                    break
                time.sleep(0.5)
    
    def start_monitoring(self):
        """Start the background monitoring thread"""
        self.monitor_thread = threading.Thread(target=self.monitor_system, daemon=True)
        self.monitor_thread.start()
        print(f"✅ System monitoring started (checking every {self.check_interval}s)")
        print(f"   Temperature threshold: {self.temp_threshold}°C")
        print(f"   CPU usage threshold: {self.usage_threshold}%")
        print(f"   Cooldown time: {self.cooldown_time}s")
    
    def wait_if_needed(self):
        """Check if scan is paused and wait"""
        while self.scan_paused and self.running:
            time.sleep(0.5)
    
    def cleanup(self):
        """Cleanup on exit"""
        self.running = False
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=2)
        
        # Print statistics
        if self.total_cooldowns > 0:
            print(f"\n📊 Thermal Protection Statistics:")
            print(f"   Total cooldowns: {self.total_cooldowns}")
            print(f"   Total cooldown time: {self.total_cooldown_time:.1f}s")
            print(f"   Average cooldown: {self.total_cooldown_time/self.total_cooldowns:.1f}s")

# ============================================================================
# Signal Handlers
# ============================================================================

class GracefulExit:
    """Handle Ctrl+C gracefully"""
    
    def __init__(self):
        self.exit_now = False
        signal.signal(signal.SIGINT, self.exit_gracefully)
        signal.signal(signal.SIGTERM, self.exit_gracefully)
    
    def exit_gracefully(self, signum, frame):
        print("\n\n⚠️  Received interrupt signal. Cleaning up...")
        self.exit_now = True
    
    def should_exit(self) -> bool:
        return self.exit_now

# ============================================================================
# Data Structures (simplified for space)
# ============================================================================

class SecretSeverity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

@dataclass(slots=True)
class SecretMatch:
    pattern_name: str
    secret_value: str
    line_number: int
    file_path: str
    severity: SecretSeverity
    entropy_score: float = 0.0

@dataclass(slots=True)
class Pattern:
    name: str
    regex: re.Pattern
    severity: SecretSeverity

# ============================================================================
# Pattern Database (compressed)
# ============================================================================

class PatternDatabase:
    @staticmethod
    def get_all_patterns() -> List[Tuple[str, str, SecretSeverity]]:
        return [
            # AWS
            ("AWS Access Key", r"(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9])", SecretSeverity.CRITICAL),
            ("AWS Secret Key", r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])", SecretSeverity.CRITICAL),
            
            # Azure
            ("Azure Storage Key", r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/=]{88}(?![A-Za-z0-9+/=])", SecretSeverity.CRITICAL),
            ("Azure Connection", r"DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}", SecretSeverity.CRITICAL),
            
            # GCP
            ("GCP API Key", r"AIza[0-9A-Za-z-_]{35}", SecretSeverity.CRITICAL),
            
            # Payment
            ("Stripe Live", r"sk_live_[0-9a-zA-Z]{24}", SecretSeverity.CRITICAL),
            ("Stripe Test", r"sk_test_[0-9a-zA-Z]{24}", SecretSeverity.CRITICAL),
            ("PayPal Secret", r"(?<![A-Za-z0-9])[A-Za-z0-9]{40}(?![A-Za-z0-9])", SecretSeverity.CRITICAL),
            
            # Database
            ("PostgreSQL", r"postgres(ql)?://[^:]+:[^@]+@[^:]+:[0-9]+/[^\s]+", SecretSeverity.CRITICAL),
            ("MySQL", r"mysql://[^:]+:[^@]+@[^:]+:[0-9]+/[^\s]+", SecretSeverity.CRITICAL),
            ("MongoDB", r"mongodb(\+srv)?://[^:]+:[^@]+@[^:]+(:[0-9]+)?/[^\s]+", SecretSeverity.CRITICAL),
            
            # DevOps
            ("GitHub PAT", r"ghp_[A-Za-z0-9]{36}", SecretSeverity.CRITICAL),
            ("GitLab PAT", r"glpat-[0-9a-zA-Z_-]{20}", SecretSeverity.CRITICAL),
            
            # Communication
            ("Slack Webhook", r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+", SecretSeverity.CRITICAL),
            ("Discord Webhook", r"https://discord(app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+", SecretSeverity.CRITICAL),
            
            # Auth
            ("JWT Token", r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*", SecretSeverity.CRITICAL),
            
            # Private Keys
            ("RSA Private", r"-----BEGIN RSA PRIVATE KEY-----", SecretSeverity.CRITICAL),
            ("SSH Private", r"-----BEGIN OPENSSH PRIVATE KEY-----", SecretSeverity.CRITICAL),
        ]

# ============================================================================
# Scanner with Thermal Awareness
# ============================================================================

class ThermalAwareScanner:
    """Scanner that respects system thermal limits"""
    
    def __init__(self, 
                 protection: SystemProtection,
                 entropy_threshold: float = 3.8,
                 min_length: int = 10,
                 chunk_size: int = 512 * 1024):  # 512KB chunks for better thermal management
        self.protection = protection
        self.entropy_threshold = entropy_threshold
        self.min_length = min_length
        self.chunk_size = chunk_size
        self.patterns = self._compile_patterns()
        self.files_scanned = 0
        self.total_chunks = 0
        self.scan_start_time = time.time()
        
    def _compile_patterns(self) -> List[Pattern]:
        compiled = []
        for name, pattern, severity in PatternDatabase.get_all_patterns():
            try:
                compiled.append(Pattern(
                    name=name,
                    regex=re.compile(pattern),
                    severity=severity
                ))
            except re.error:
                pass
        return compiled
    
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
    
    def scan_line(self, line: str, file_path: str, line_num: int) -> List[SecretMatch]:
        """Scan a single line"""
        matches = []
        
        # Check regex patterns
        for pattern in self.patterns:
            for match in pattern.regex.finditer(line):
                secret = match.group()
                matches.append(SecretMatch(
                    pattern_name=pattern.name,
                    secret_value=secret[:100],
                    line_number=line_num,
                    file_path=file_path,
                    severity=pattern.severity
                ))
        
        # Check entropy for long strings
        if len(line) >= 16:
            words = re.findall(r'[A-Za-z0-9\-_=+/]{16,}', line)
            for word in words:
                entropy = self.calculate_entropy(word)
                if entropy >= self.entropy_threshold:
                    matches.append(SecretMatch(
                        pattern_name="High Entropy String",
                        secret_value=word[:100],
                        line_number=line_num,
                        file_path=file_path,
                        severity=SecretSeverity.MEDIUM,
                        entropy_score=entropy
                    ))
        
        return matches
    
    def scan_file(self, file_path: str) -> Generator[SecretMatch, None, None]:
        """Scan a file with thermal awareness"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                line_num = 0
                chunk_lines = []
                chunk_start_line = 0
                
                for line in f:
                    # Check if we should exit
                    if hasattr(self, 'exit_now') and self.exit_now:
                        return
                    
                    # Check if we need to cool down
                    self.protection.wait_if_needed()
                    
                    line = line.rstrip('\n')
                    line_num += 1
                    chunk_lines.append((line_num, line))
                    
                    # Process in chunks to check temperature between chunks
                    if len(chunk_lines) >= 100:  # Process 100 lines at a time
                        for l_num, l in chunk_lines:
                            matches = self.scan_line(l, file_path, l_num)
                            for match in matches:
                                yield match
                        
                        # Update stats
                        self.total_chunks += 1
                        chunk_lines = []
                        
                        # Small delay to let system breathe if needed
                        time.sleep(0.001)
                
                # Process remaining lines
                for l_num, l in chunk_lines:
                    matches = self.scan_line(l, file_path, l_num)
                    for match in matches:
                        yield match
                
        except Exception as e:
            print(f"Error scanning {file_path}: {e}")
    
    def scan_directory(self, path: str) -> Generator[SecretMatch, None, None]:
        """Scan directory with thermal awareness"""
        text_extensions = {'.py', '.js', '.ts', '.java', '.json', '.yml', '.yaml', 
                          '.env', '.txt', '.md', '.conf', '.config', '.properties'}
        
        for root, dirs, files in os.walk(path):
            # Skip common directories
            dirs[:] = [d for d in dirs if d not in {'.git', 'node_modules', 'venv', '__pycache__'}]
            
            for file in files:
                # Check exit flag
                if hasattr(self, 'exit_now') and self.exit_now:
                    return
                
                # Check thermal status before each file
                self.protection.wait_if_needed()
                
                ext = os.path.splitext(file)[1].lower()
                if ext in text_extensions:
                    file_path = os.path.join(root, file)
                    self.files_scanned += 1
                    
                    # Progress update
                    if self.files_scanned % 50 == 0:
                        elapsed = time.time() - self.scan_start_time
                        rate = self.files_scanned / elapsed if elapsed > 0 else 0
                        print(f"📁 Scanned {self.files_scanned} files | Rate: {rate:.1f} files/sec")
                    
                    # Scan file
                    for match in self.scan_file(file_path):
                        yield match

# ============================================================================
# Main Application
# ============================================================================

def main():
    parser = argparse.ArgumentParser(description='Secret Scanner with Thermal Protection')
    parser.add_argument('path', help='Path to scan')
    parser.add_argument('--temp-threshold', type=float, default=85.0, help='CPU temperature threshold (°C)')
    parser.add_argument('--cpu-threshold', type=float, default=90.0, help='CPU usage threshold (%)')
    parser.add_argument('--cooldown', type=int, default=5, help='Cooldown time (seconds)')
    parser.add_argument('--priority', choices=['low', 'below_normal', 'idle'], default='below_normal', 
                       help='Process priority')
    parser.add_argument('--output', choices=['text', 'json'], default='text')
    
    args = parser.parse_args()
    
    print("=" * 70)
    print("WORLD'S #1 SECRET SCANNER - WITH THERMAL PROTECTION")
    print("=" * 70)
    print(f"Target system: i3 3rd Gen Laptop")
    print(f"Goal: Steady, unstoppable scan without thermal throttling")
    print("=" * 70)
    
    # Initialize system protection
    protection = SystemProtection(
        temp_threshold=args.temp_threshold,
        usage_threshold=args.cpu_threshold,
        cooldown_time=args.cooldown
    )
    
    # Start monitoring
    protection.start_monitoring()
    
    # Initialize graceful exit handler
    exit_handler = GracefulExit()
    
    # Initialize scanner
    scanner = ThermalAwareScanner(protection=protection)
    scanner.exit_now = lambda: exit_handler.should_exit()
    
    # Collect matches
    matches = []
    match_count = 0
    
    print(f"\n🔍 Scanning: {args.path}")
    print("-" * 70)
    
    try:
        # Start scan
        scan_start = time.time()
        
        if os.path.isfile(args.path):
            generator = scanner.scan_file(args.path)
        else:
            generator = scanner.scan_directory(args.path)
        
        for match in generator:
            # Check for exit
            if exit_handler.should_exit():
                break
            
            matches.append(match)
            match_count += 1
            
            # Print as we find (but not too many)
            if match_count <= 10:
                print(f"  🔴 {match.pattern_name} in {os.path.basename(match.file_path)}:{match.line_number}")
            elif match_count == 11:
                print("  ... (further matches will be counted silently)")
        
        scan_time = time.time() - scan_start
        
        # Final report
        print("\n" + "=" * 70)
        print("SCAN COMPLETE")
        print("=" * 70)
        print(f"Files scanned: {scanner.files_scanned}")
        print(f"Secrets found: {match_count}")
        print(f"Scan time: {scan_time:.1f} seconds")
        print(f"Average rate: {scanner.files_scanned/scan_time:.1f} files/sec")
        
        # Thermal stats
        if protection.total_cooldowns > 0:
            print(f"\n🌡️  Thermal events: {protection.total_cooldowns}")
            print(f"   Total cooldown time: {protection.total_cooldown_time:.1f}s")
            print(f"   Time lost to cooling: {protection.total_cooldown_time/scan_time*100:.1f}%")
        
        # List found secrets by severity
        if matches:
            print("\n📋 SUMMARY BY SEVERITY:")
            critical = len([m for m in matches if m.severity == SecretSeverity.CRITICAL])
            high = len([m for m in matches if m.severity == SecretSeverity.HIGH])
            medium = len([m for m in matches if m.severity == SecretSeverity.MEDIUM])
            
            print(f"  🔴 CRITICAL: {critical}")
            print(f"  🟠 HIGH: {high}")
            print(f"  🟡 MEDIUM: {medium}")
        
    except KeyboardInterrupt:
        print("\n\n⚠️ Scan interrupted by user")
    finally:
        protection.cleanup()
    
    # Return exit code
    critical_count = len([m for m in matches if m.severity == SecretSeverity.CRITICAL])
    if critical_count > 0:
        return 2
    elif matches:
        return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())
    