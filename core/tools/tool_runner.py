"""Tool runner adapter for safe command execution"""
import subprocess
import shlex
from pathlib import Path
from typing import Dict, Any, Optional, List
from datetime import datetime
import re


class ToolRunnerResult:
    """Result from tool execution"""
    def __init__(
        self,
        command: str,
        stdout: str,
        stderr: str,
        exit_code: int,
        duration_seconds: float,
        dry_run: bool = False
    ):
        self.command = command
        self.stdout = stdout
        self.stderr = stderr
        self.exit_code = exit_code
        self.duration_seconds = duration_seconds
        self.dry_run = dry_run
        self.success = exit_code == 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "command": self.command,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "exit_code": self.exit_code,
            "duration_seconds": self.duration_seconds,
            "dry_run": self.dry_run,
            "success": self.success
        }


class ToolRunner:
    """
    Safe tool execution with allowlist enforcement
    Integrates with Claude terminal for approved operations
    """

    def __init__(self, allowlist_config: Optional[Dict] = None, dry_run: bool = False):
        self.dry_run = dry_run
        self.allowlist = allowlist_config or self._default_allowlist()

    def _default_allowlist(self) -> Dict[str, List[str]]:
        """Default allowlist of safe commands"""
        return {
            "recon": [
                "subfinder -d {domain} -silent",
                "httpx -l {input_file} -silent -status-code -title",
                "nmap -p- {target} -oN {output_file}",
                "whatweb {url} --log-json {output_file}"
            ],
            "code_search": [
                "grep -r {pattern} {directory}",
                "rg {pattern} {directory} --json",
                "find {directory} -name {pattern} -type f"
            ],
            "apk_analysis": [
                "apktool d {apk_file} -o {output_dir}",
                "jadx -d {output_dir} {apk_file}",
                "aapt dump badging {apk_file}",
                "unzip -l {apk_file}"
            ],
            "static_analysis": [
                "semgrep --config auto {directory} --json -o {output_file}",
                "trivy fs {directory} --format json -o {output_file}",
                "bandit -r {directory} -f json -o {output_file}"
            ]
        }

    def is_allowed(self, command: str, category: str = "recon") -> bool:
        """Check if command matches allowlist"""
        if category not in self.allowlist:
            return False

        # Extract base command
        base_cmd = command.split()[0] if command else ""

        # Check if any allowlist pattern matches
        for pattern in self.allowlist[category]:
            pattern_base = pattern.split()[0]
            if base_cmd == pattern_base:
                return True

        return False

    def sanitize_params(self, params: Dict[str, str]) -> Dict[str, str]:
        """
        Sanitize input parameters to prevent injection

        Args:
            params: Dict of parameter name -> value

        Returns:
            Sanitized params dict
        """
        sanitized = {}
        for key, value in params.items():
            # Remove dangerous characters
            value = re.sub(r'[;&|`$()]', '', str(value))
            # Remove newlines
            value = value.replace('\n', '').replace('\r', '')
            # Limit length
            value = value[:500]
            sanitized[key] = value

        return sanitized

    def execute(
        self,
        command_template: str,
        params: Dict[str, str],
        category: str = "recon",
        timeout: int = 300,
        cwd: Optional[Path] = None
    ) -> ToolRunnerResult:
        """
        Execute a command with parameter substitution

        Args:
            command_template: Command template with {param} placeholders
            params: Parameters to substitute
            category: Command category for allowlist checking
            timeout: Command timeout in seconds
            cwd: Working directory

        Returns:
            ToolRunnerResult

        Raises:
            ValueError: If command not allowed
            subprocess.TimeoutExpired: If command times out
        """
        # Sanitize parameters
        safe_params = self.sanitize_params(params)

        # Build command
        try:
            command = command_template.format(**safe_params)
        except KeyError as e:
            raise ValueError(f"Missing parameter: {e}")

        # Check allowlist
        if not self.is_allowed(command, category):
            raise ValueError(f"Command not in allowlist: {command}")

        # Dry run mode
        if self.dry_run:
            return ToolRunnerResult(
                command=command,
                stdout=f"[DRY RUN] Would execute: {command}",
                stderr="",
                exit_code=0,
                duration_seconds=0.0,
                dry_run=True
            )

        # Execute command
        start_time = datetime.now()

        try:
            result = subprocess.run(
                shlex.split(command),
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=cwd
            )

            duration = (datetime.now() - start_time).total_seconds()

            return ToolRunnerResult(
                command=command,
                stdout=result.stdout,
                stderr=result.stderr,
                exit_code=result.returncode,
                duration_seconds=duration,
                dry_run=False
            )

        except subprocess.TimeoutExpired:
            duration = (datetime.now() - start_time).total_seconds()
            return ToolRunnerResult(
                command=command,
                stdout="",
                stderr=f"Command timed out after {timeout}s",
                exit_code=-1,
                duration_seconds=duration,
                dry_run=False
            )

    def execute_script(
        self,
        script_path: Path,
        args: List[str] = None,
        timeout: int = 300,
        category: str = "recon"
    ) -> ToolRunnerResult:
        """
        Execute a pre-approved script

        Args:
            script_path: Path to script
            args: Script arguments
            timeout: Timeout in seconds
            category: Category for logging

        Returns:
            ToolRunnerResult
        """
        if not script_path.exists():
            raise ValueError(f"Script not found: {script_path}")

        args = args or []
        # Sanitize args
        safe_args = [self.sanitize_params({"arg": arg})["arg"] for arg in args]

        command = [str(script_path)] + safe_args

        if self.dry_run:
            return ToolRunnerResult(
                command=" ".join(command),
                stdout=f"[DRY RUN] Would execute script: {script_path}",
                stderr="",
                exit_code=0,
                duration_seconds=0.0,
                dry_run=True
            )

        start_time = datetime.now()

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout
            )

            duration = (datetime.now() - start_time).total_seconds()

            return ToolRunnerResult(
                command=" ".join(command),
                stdout=result.stdout,
                stderr=result.stderr,
                exit_code=result.returncode,
                duration_seconds=duration,
                dry_run=False
            )

        except subprocess.TimeoutExpired:
            duration = (datetime.now() - start_time).total_seconds()
            return ToolRunnerResult(
                command=" ".join(command),
                stdout="",
                stderr=f"Script timed out after {timeout}s",
                exit_code=-1,
                duration_seconds=duration,
                dry_run=False
            )
