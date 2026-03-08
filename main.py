#!/usr/bin/env python3
"""
CyberGhost-Ultra-Scanner Main Controller
World's most advanced secret scanner with real-time thermal-aware dashboard
"""

import asyncio
import argparse
import signal
import sys
import os
import json
import time
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any
from dataclasses import asdict
import traceback
from collections import deque

# Rich terminal formatting
from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.progress import Progress, BarColumn, TextColumn, SpinnerColumn
from rich.table import Table
from rich.text import Text
from rich.live import Live
from rich import box
from rich.align import Align
from rich.columns import Columns
import psutil

# Import scanner engines
from secret_detector import ThermalAwareScanner, ThermalGuard, SecretMatch, SecretSeverity
from github_client import GitHubScanner, GitHubAPIClient, parse_github_url

# ============================================================================
# Configuration
# ============================================================================

class Config:
    """Global configuration"""
    VERSION = "1.0.0"
    NAME = "CyberGhost-Ultra-Scanner"
    
    # Thresholds
    TEMP_WARNING = 75
    TEMP_CRITICAL = 85
    CPU_WARNING = 80
    CPU_CRITICAL = 90
    
    # UI Settings
    REFRESH_RATE = 0.5  # seconds
    MAX_DISPLAY_SECRETS = 10
    HISTORY_SIZE = 60  # 30 seconds at 0.5s refresh
    
    # File paths
    REPORT_DIR = "reports"
    PROGRESS_FILE = ".scan_progress.json"

# ============================================================================
# Real-Time Dashboard
# ============================================================================

class CyberGhostDashboard:
    """Beautiful real-time dashboard for the scanner"""
    
    def __init__(self, console: Console):
        self.console = console
        self.layout = Layout()
        self.setup_layout()
        
        # Data stores
        self.secrets: List[SecretMatch] = []
        self.stats = {
            'files_scanned': 0,
            'lines_scanned': 0,
            'secrets_found': 0,
            'critical_count': 0,
            'high_count': 0,
            'medium_count': 0,
            'low_count': 0,
            'github_commits': 0,
            'github_repos': 0
        }
        
        # Temperature history for graph
        self.temp_history = deque(maxlen=Config.HISTORY_SIZE)
        self.cpu_history = deque(maxlen=Config.HISTORY_SIZE)
        
        # Start time
        self.start_time = time.time()
        
        # Scan status
        self.scanning = True
        self.current_file = ""
        self.current_commit = ""
        self.scan_mode = "local"  # local, github, or both
        
    def setup_layout(self):
        """Create the dashboard layout"""
        self.layout.split(
            Layout(name="header", size=3),
            Layout(name="main"),
            Layout(name="footer", size=3)
        )
        
        self.layout["main"].split_row(
            Layout(name="left", ratio=2),
            Layout(name="right", ratio=1)
        )
        
        self.layout["left"].split(
            Layout(name="secrets", ratio=2),
            Layout(name="progress", size=5)
        )
        
        self.layout["right"].split(
            Layout(name="system", size=10),
            Layout(name="stats", size=10),
            Layout(name="github", size=8)
        )
    
    def render_header(self) -> Panel:
        """Render the header panel"""
        title = Text(f"👻 {Config.NAME} v{Config.VERSION}", style="bold magenta")
        subtitle = Text(" The Ultimate Secret Scanner", style="cyan")
        
        # Scan time
        elapsed = time.time() - self.start_time
        time_str = f"{int(elapsed // 60):02d}:{int(elapsed % 60):02d}"
        
        header = Table.grid(expand=True)
        header.add_column(justify="left", ratio=1)
        header.add_column(justify="center", ratio=1)
        header.add_column(justify="right", ratio=1)
        
        header.add_row(
            title,
            subtitle,
            f"[yellow]⏱️ {time_str}[/yellow]"
        )
        
        return Panel(header, style="bold white", box=box.DOUBLE)
    
    def render_secrets(self) -> Panel:
        """Render the secrets found panel"""
        table = Table(
            title=f"🔴 Found Secrets ({len(self.secrets)} total)",
            box=box.ROUNDED,
            header_style="bold cyan",
            expand=True
        )
        
        table.add_column("Severity", width=10)
        table.add_column("Type", width=20)
        table.add_column("Location", width=30)
        table.add_column("Preview", width=40)
        
        # Show most recent secrets first
        for secret in self.secrets[-Config.MAX_DISPLAY_SECRETS:]:
            # Color by severity
            severity_style = {
                SecretSeverity.CRITICAL: "bold red",
                SecretSeverity.HIGH: "bold yellow",
                SecretSeverity.MEDIUM: "blue",
                SecretSeverity.LOW: "green"
            }.get(secret.severity, "white")
            
            # Truncate preview
            preview = secret.secret_value[:30] + "..." if len(secret.secret_value) > 30 else secret.secret_value
            
            table.add_row(
                f"[{severity_style}]{secret.severity.value}[/]",
                secret.pattern_name[:18] + "..." if len(secret.pattern_name) > 18 else secret.pattern_name,
                f"{Path(secret.file_path).name}:{secret.line_number}",
                preview
            )
        
        if not self.secrets:
            table.add_row("", "[dim]No secrets found yet[/]", "", "")
        
        return Panel(table, border_style="cyan")
    
    def render_system_health(self) -> Panel:
        """Render system health panel with temperature graph"""
        # Get current readings
        temp = self._get_cpu_temp()
        cpu = psutil.cpu_percent()
        memory = psutil.virtual_memory().percent
        
        # Add to history
        self.temp_history.append(temp)
        self.cpu_history.append(cpu)
        
        # Create temperature bar
        temp_color = "green"
        if temp >= Config.TEMP_CRITICAL:
            temp_color = "bold red"
        elif temp >= Config.TEMP_WARNING:
            temp_color = "yellow"
        
        # Create CPU bar
        cpu_color = "green"
        if cpu >= Config.CPU_CRITICAL:
            cpu_color = "bold red"
        elif cpu >= Config.CPU_WARNING:
            cpu_color = "yellow"
        
        # Create mini graph
        graph = self._create_mini_graph(self.temp_history, self.cpu_history)
        
        # Thermal guard status
        thermal_status = "🟢 ACTIVE" if temp < Config.TEMP_CRITICAL else "🔴 COOLDOWN"
        
        table = Table(show_header=False, box=box.SIMPLE, padding=(0, 1))
        table.add_column("Metric", style="cyan")
        table.add_column("Value")
        table.add_column("Status")
        
        table.add_row(
            "🌡️  Temperature",
            f"[{temp_color}]{temp:.1f}°C[/]",
            thermal_status
        )
        table.add_row(
            "⚡ CPU Usage",
            f"[{cpu_color}]{cpu:.1f}%[/]",
            self._get_cpu_emoji(cpu)
        )
        table.add_row(
            "💾 Memory",
            f"{memory:.1f}%",
            "🟢 OK" if memory < 80 else "🟡 High"
        )
        table.add_row("📊 Trend", graph, "")
        
        return Panel(table, title="🖥️  System Health", border_style="green")
    
    def _create_mini_graph(self, temp_data, cpu_data, width=20) -> str:
        """Create a mini sparkline graph"""
        if not temp_data:
            return "No data"
        
        # Normalize to width
        chars = []
        max_temp = max(max(temp_data), 40)  # Min 40°C for scaling
        
        for i, temp in enumerate(list(temp_data)[-width:]):
            # Calculate height (0-4)
            height = int((temp / max_temp) * 4)
            
            if i < len(cpu_data):
                cpu = list(cpu_data)[-width:][i]
                # Combine indicators
                if cpu > Config.CPU_WARNING:
                    chars.append("🔴")
                elif temp > Config.TEMP_WARNING:
                    chars.append("🟡")
                else:
                    chars.append("🟢")
            else:
                chars.append("⚪")
        
        return "".join(chars[-width:])
    
    def _get_cpu_temp(self) -> float:
        """Get CPU temperature safely"""
        try:
            if os.path.exists("/sys/class/thermal/thermal_zone0/temp"):
                with open("/sys/class/thermal/thermal_zone0/temp") as f:
                    return float(f.read().strip()) / 1000.0
        except:
            pass
        return 0.0
    
    def _get_cpu_emoji(self, cpu: float) -> str:
        """Get emoji based on CPU usage"""
        if cpu < 30:
            return "💤 Idle"
        elif cpu < 60:
            return "⚡ Normal"
        elif cpu < 85:
            return "🔥 High"
        else:
            return "🚨 Critical"
    
    def render_stats(self) -> Panel:
        """Render statistics panel"""
        table = Table(show_header=False, box=box.SIMPLE)
        table.add_column("Metric", style="cyan")
        table.add_column("Value", justify="right")
        
        table.add_row("📁 Files", f"{self.stats['files_scanned']:,}")
        table.add_row("📝 Lines", f"{self.stats['lines_scanned']:,}")
        table.add_row("🔍 Secrets", f"{self.stats['secrets_found']}")
        
        # Severity breakdown
        if self.stats['secrets_found'] > 0:
            table.add_section()
            table.add_row("[red]CRITICAL[/]", f"[red]{self.stats['critical_count']}[/]")
            table.add_row("[yellow]HIGH[/]", f"[yellow]{self.stats['high_count']}[/]")
            table.add_row("[blue]MEDIUM[/]", f"[blue]{self.stats['medium_count']}[/]")
            table.add_row("[green]LOW[/]", f"[green]{self.stats['low_count']}[/]")
        
        # Speed
        elapsed = time.time() - self.start_time
        if elapsed > 0 and self.stats['files_scanned'] > 0:
            files_per_sec = self.stats['files_scanned'] / elapsed
            table.add_section()
            table.add_row("⚡ Speed", f"{files_per_sec:.1f} files/s")
        
        return Panel(table, title="📊 Statistics", border_style="blue")
    
    def render_github(self) -> Panel:
        """Render GitHub scanning panel"""
        table = Table(show_header=False, box=box.SIMPLE)
        table.add_column("Metric", style="cyan")
        table.add_column("Value")
        
        table.add_row("📚 Repos", f"{self.stats['github_repos']}")
        table.add_row("📜 Commits", f"{self.stats['github_commits']}")
        
        if self.current_commit:
            table.add_row("🔍 Current", f"{self.current_commit[:8]}...")
        
        return Panel(table, title="🐙 GitHub Scanner", border_style="yellow")
    
    def render_progress(self) -> Panel:
        """Render progress bar"""
        progress = Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            expand=True
        )
        
        # Create appropriate progress display
        if self.scan_mode == "local":
            task = progress.add_task(
                f"[cyan]Scanning: {Path(self.current_file).name}",
                total=100,
                completed=50  # Placeholder
            )
        elif self.scan_mode == "github":
            task = progress.add_task(
                f"[yellow]GitHub: {self.current_commit}",
                total=100,
                completed=30
            )
        else:
            task = progress.add_task(
                "[green]Multi-mode scanning...",
                total=100,
                completed=0
            )
        
        return Panel(progress, title="🚀 Scan Progress", border_style="magenta")
    
    def render_footer(self) -> Panel:
        """Render footer with commands"""
        text = Text()
        text.append(" Ctrl+C ", style="reverse")
        text.append(" to save progress and exit")
        text.append(" | ")
        text.append(" 🔄 Live Dashboard", style="green")
        return Panel(Align.center(text), style="dim")
    
    def update(self):
        """Update the dashboard"""
        self.layout["header"].update(self.render_header())
        self.layout["secrets"].update(self.render_secrets())
        self.layout["system"].update(self.render_system_health())
        self.layout["stats"].update(self.render_stats())
        self.layout["github"].update(self.render_github())
        self.layout["progress"].update(self.render_progress())
        self.layout["footer"].update(self.render_footer())
    
    def add_secret(self, secret: SecretMatch):
        """Add a secret to the display"""
        self.secrets.append(secret)
        self.stats['secrets_found'] += 1
        
        # Update severity counts
        if secret.severity == SecretSeverity.CRITICAL:
            self.stats['critical_count'] += 1
        elif secret.severity == SecretSeverity.HIGH:
            self.stats['high_count'] += 1
        elif secret.severity == SecretSeverity.MEDIUM:
            self.stats['medium_count'] += 1
        else:
            self.stats['low_count'] += 1

# ============================================================================
# Main Controller
# ============================================================================

class CyberGhostController:
    """Main controller orchestrating all scanners"""
    
    def __init__(self, args):
        self.args = args
        self.console = Console()
        self.dashboard = CyberGhostDashboard(self.console)
        
        # Scan state
        self.secrets: List[SecretMatch] = []
        self.running = True
        self.paused = False
        self.start_time = time.time()
        
        # Initialize components
        self.thermal_guard = ThermalGuard(
            temp_threshold=args.temp_threshold,
            cpu_threshold=args.cpu_threshold,
            cooldown_time=args.cooldown
        ).start()
        
        self.local_scanner = ThermalAwareScanner(
            thermal_guard=self.thermal_guard,
            entropy_threshold=args.entropy,
            use_entropy=not args.no_entropy
        )
        
        self.github_scanner = None
        self.github_client = None
        
        # Set up signal handlers
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        # Create report directory
        if args.save:
            Path(Config.REPORT_DIR).mkdir(exist_ok=True)
    
    def signal_handler(self, signum, frame):
        """Handle Ctrl+C gracefully"""
        self.console.print("\n[yellow]⚠️  Received interrupt signal. Saving progress...[/yellow]")
        self.running = False
    
    async def setup_github(self):
        """Set up GitHub scanner if credentials provided"""
        if not self.args.token or not self.args.repo:
            return
        
        try:
            owner, repo, branch = parse_github_url(self.args.repo)
            branch = self.args.branch or branch
            
            self.github_client = GitHubAPIClient(
                token=self.args.token,
                max_concurrent=2  # i3 optimized
            )
            
            await self.github_client.__aenter__()
            
            self.github_scanner = GitHubScanner(self.github_client)
            # Share patterns from local scanner
            self.github_scanner.set_patterns(self.local_scanner.patterns)
            
            self.console.print(f"[green]✅ GitHub scanner initialized for {owner}/{repo}[/green]")
            return owner, repo, branch
            
        except Exception as e:
            self.console.print(f"[red]❌ GitHub setup failed: {e}[/red]")
            return None
    
    async def scan_local(self, path: str):
        """Run local file scanning"""
        self.dashboard.scan_mode = "local"
        path = Path(path)
        
        if path.is_file():
            files = [str(path)]
        else:
            files = []
            for root, dirs, _ in os.walk(path):
                dirs[:] = [d for d in dirs if d not in {
                    '.git', 'node_modules', 'venv', '__pycache__'
                }]
                for file in os.listdir(root):
                    file_path = os.path.join(root, file)
                    if os.path.isfile(file_path):
                        files.append(file_path)
        
        for file_path in files:
            if not self.running:
                break
            
            self.dashboard.current_file = file_path
            
            # Scan file
            for secret in self.local_scanner.scan_file(file_path):
                if not self.running:
                    break
                
                self.secrets.append(secret)
                self.dashboard.add_secret(secret)
                self.dashboard.stats['files_scanned'] = self.local_scanner.stats['files_scanned']
                self.dashboard.stats['lines_scanned'] = self.local_scanner.stats['lines_scanned']
            
            # Small delay for UI
            await asyncio.sleep(0.01)
    
    async def scan_github(self, owner: str, repo: str, branch: str):
        """Run GitHub scanning"""
        if not self.github_scanner:
            return
        
        self.dashboard.scan_mode = "both"
        
        try:
            async for match in self.github_scanner.scan_repository(
                owner, repo, branch,
                max_commits=self.args.depth
            ):
                if not self.running:
                    break
                
                # Convert to SecretMatch
                secret = SecretMatch(
                    pattern_name=match.pattern_name,
                    secret_value=match.secret_value,
                    line_number=match.line_number,
                    file_path=f"github:{match.repo_name}/{match.file_path}",
                    severity=match.severity,
                    entropy_score=match.entropy_score
                )
                
                self.secrets.append(secret)
                self.dashboard.add_secret(secret)
                self.dashboard.stats['github_commits'] += 1
                self.dashboard.current_commit = match.commit_sha[:8]
                
        except Exception as e:
            self.console.print(f"[red]GitHub scan error: {e}[/red]")
    
    async def run(self):
        """Main execution loop"""
        # Print banner
        self.console.print(f"""
[bold magenta]
   ╔══════════════════════════════════════════════════════════╗
   ║     CyberGhost-Ultra-Scanner v{Config.VERSION} - World's #1 Secret Scanner   ║
   ║         🔥 Thermal-Aware | 🚀 Ultra-Fast | 🛡️  Safe        ║
   ╚══════════════════════════════════════════════════════════╝
[/bold magenta]
        """)
        
        # Setup GitHub
        github_info = await self.setup_github()
        
        # Start live dashboard
        with Live(self.dashboard.layout, refresh_per_second=2, screen=True):
            self.dashboard.scanning = True
            
            # Run scans concurrently
            tasks = []
            
            # Local scan
            if os.path.exists(self.args.path):
                tasks.append(self.scan_local(self.args.path))
            else:
                self.console.print(f"[red]❌ Path not found: {self.args.path}[/red]")
            
            # GitHub scan
            if github_info:
                owner, repo, branch = github_info
                tasks.append(self.scan_github(owner, repo, branch))
            
            if tasks:
                await asyncio.gather(*tasks)
        
        # Save results
        await self.save_results()
    
    async def save_results(self):
        """Save scan results to file"""
        if not self.args.save:
            return
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = Path(Config.REPORT_DIR) / f"scan_{timestamp}.json"
        
        report = {
            "metadata": {
                "scanner": Config.NAME,
                "version": Config.VERSION,
                "start_time": datetime.fromtimestamp(self.start_time).isoformat(),
                "end_time": datetime.now().isoformat(),
                "duration": time.time() - self.start_time,
                "args": vars(self.args)
            },
            "statistics": self.dashboard.stats,
            "thermal_stats": self.thermal_guard.get_stats(),
            "local_stats": self.local_scanner.get_stats(),
            "secrets": [s.to_dict() for s in self.secrets]
        }
        
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        self.console.print(f"\n[green]✅ Report saved to: {report_file}[/green]")
        
        # Print summary
        critical = self.dashboard.stats['critical_count']
        if critical > 0:
            self.console.print(f"[bold red]⚠️  Found {critical} CRITICAL secrets![/bold red]")

# ============================================================================
# Main Entry Point
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="CyberGhost-Ultra-Scanner - World's #1 Secret Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py /path/to/code
  python main.py /path/to/code --repo https://github.com/user/repo --token ghp_xxx
  python main.py /path/to/code --temp-threshold 80 --cpu-threshold 85
  python main.py /path/to/code --depth 500 --no-entropy
        """
    )
    
    # Scan target
    parser.add_argument('path', help='Local path to scan')
    
    # GitHub options
    parser.add_argument('--repo', help='GitHub repository URL')
    parser.add_argument('--token', help='GitHub token')
    parser.add_argument('--branch', default='main', help='GitHub branch (default: main)')
    parser.add_argument('--depth', type=int, default=100, help='Commits depth (default: 100)')
    
    # Scanner options
    parser.add_argument('--entropy', type=float, default=3.8, help='Entropy threshold')
    parser.add_argument('--no-entropy', action='store_true', help='Disable entropy detection')
    
    # Thermal options
    parser.add_argument('--temp-threshold', type=float, default=85, help='Temperature threshold (°C)')
    parser.add_argument('--cpu-threshold', type=float, default=90, help='CPU threshold (%)')
    parser.add_argument('--cooldown', type=int, default=5, help='Cooldown seconds')
    
    # Output options
    parser.add_argument('--no-save', action='store_true', help='Disable report saving')
    parser.add_argument('--quiet', action='store_true', help='Minimal output')
    
    args = parser.parse_args()
    args.save = not args.no_save
    
    # Run controller
    controller = CyberGhostController(args)
    
    try:
        asyncio.run(controller.run())
    except KeyboardInterrupt:
        pass
    except Exception as e:
        console = Console()
        console.print(f"[bold red]❌ Fatal error: {e}[/bold red]")
        if not args.quiet:
            traceback.print_exc()
        return 1
    
    # Exit codes for CI/CD
    if controller.dashboard.stats['critical_count'] > 0:
        return 2  # Critical secrets found
    elif controller.dashboard.stats['secrets_found'] > 0:
        return 1  # Secrets found
    return 0  # Clean

if __name__ == "__main__":
    sys.exit(main())
    