"""APK Analyzer Agent - Android Security Analysis using APKSlayer"""
import json
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List

from agents.base_agent import BaseAgent, RunResult
from core.schemas import Task
from core.telegram_notifier import notify_apk_analysis_complete
from core.apk_downloader import download_apk


class APKAnalyzerAgent(BaseAgent):
    """
    APK Analyzer Agent - Android Security Vulnerability Scanner

    Uses APKSlayer for comprehensive Android app security analysis:
    - 77+ vulnerability patterns (OWASP Mobile Top 10)
    - Manifest analysis & permission review
    - Intent, WebView, ContentProvider security checks
    - Hardcoded credentials & API key detection
    - Certificate analysis & signature verification
    - Attack surface mapping with exported components
    - Dynamic analysis with Frida instrumentation
    - Interactive HTML reports with visualizations
    """

    def __init__(self, dry_run: bool = False):
        super().__init__(name="apk_analyzer", dry_run=dry_run)
        self.apkslayer_path = Path(__file__).parent.parent.parent / "tools" / "apk-analyzer"

    def plan(self, context: Dict[str, Any]) -> List[Task]:
        """Not used in simplified architecture"""
        return []

    def run(self, task: Task, run_id: str) -> RunResult:
        """Execute APK analysis using APKSlayer"""
        logger, tracker, artifact_dir = self._setup_run(run_id, task.id)

        logger.log_task_start(task.id, task.type.value)
        start_time = datetime.now()

        try:
            # Extract APK path from task inputs
            apk_path = task.inputs.get('apk_path')
            apk_url = task.inputs.get('apk_url')

            if not apk_path and not apk_url:
                raise ValueError("No APK path or URL specified in task inputs")

            # Download APK if URL provided
            if apk_url:
                logger.info(f"Downloading APK from: {apk_url}")
                apk_path = self._download_apk(apk_url, artifact_dir, logger)

            if not Path(apk_path).exists():
                raise FileNotFoundError(f"APK file not found: {apk_path}")

            apk_name = Path(apk_path).name
            logger.info(f"Starting APKSlayer analysis for: {apk_name}")

            # Prepare output directory
            output_dir = artifact_dir / "apkslayer_output"
            output_dir.mkdir(exist_ok=True)

            if self.dry_run:
                logger.info(f"[DRY RUN] Would analyze: {apk_path}")
                results = self._generate_mock_results(apk_name)
            else:
                # Run APKSlayer
                results = self._run_apkslayer(apk_path, output_dir, logger)

            # Save results as artifact
            results_file = self._save_json_artifact(
                results,
                "apkslayer_results.json",
                artifact_dir
            )

            # APKSlayer uses 'findings' not 'vulnerabilities'
            vulnerabilities = results.get('findings', results.get('vulnerabilities', []))

            artifact = tracker.register(
                results_file,
                artifact_type="vulnerability_report",
                task_id=task.id,
                metadata={
                    "apk_name": apk_name,
                    "vulnerabilities": len(vulnerabilities),
                    "total_findings": results.get('total_findings', len(vulnerabilities)),
                }
            )

            logger.log_artifact(artifact.artifact_id, "vulnerability_report", str(results_file))

            # APKSlayer uses 'findings' not 'vulnerabilities'
            findings = results.get('findings', results.get('vulnerabilities', []))

            duration = (datetime.now() - start_time).total_seconds()
            logger.log_task_complete(task.id, duration, {
                "vulnerabilities": len(findings),
                "total_findings": results.get('total_findings', len(findings)),
                "apk_name": apk_name
            })

            # Send Telegram notification
            try:
                # Get HTML report path from results
                html_report_path = None
                if results.get('html_report'):
                    html_report_path = Path(results['html_report'])

                notify_apk_analysis_complete(
                    apk_name=apk_name,
                    run_id=run_id,
                    json_report_path=results_file,
                    html_report_path=html_report_path,
                    results=results
                )
                logger.info("Telegram notification sent for APK analysis")
            except Exception as e:
                logger.warning(f"Failed to send Telegram notification: {e}")

            return RunResult(
                success=True,
                artifacts=[artifact.artifact_id],
                metadata={
                    "apk_name": apk_name,
                    "findings": results
                }
            )

        except Exception as e:
            logger.error(f"APK analysis failed: {str(e)}", task_id=task.id)
            return RunResult(success=False, error=str(e))

    def _run_apkslayer(self, apk_path: str, output_dir: Path, logger) -> Dict[str, Any]:
        """Run APKSlayer tool"""
        logger.info(f"Launching APKSlayer for {apk_path}")

        # Convert to absolute path since APKSlayer runs from different directory
        abs_apk_path = str(Path(apk_path).absolute())
        abs_output_dir = str(Path(output_dir).absolute())

        logger.info(f"Absolute APK path: {abs_apk_path}")
        logger.info(f"Absolute output dir: {abs_output_dir}")

        # APKSlayer uses: python3 main.py scan <apk> --out <dir>
        cmd = [
            "python3", "main.py",
            "scan",
            abs_apk_path,
            "--out", abs_output_dir,
            "--no-update"  # Skip threat intel update for faster analysis
        ]

        logger.info(f"Command: {' '.join(cmd)}")

        try:
            result = subprocess.run(
                cmd,
                cwd=str(self.apkslayer_path),
                capture_output=True,
                text=True,
                timeout=600  # 10 minute timeout for large APKs
            )

            logger.info(f"APKSlayer stdout: {result.stdout[:500]}")

            if result.returncode != 0:
                logger.warning(f"APKSlayer exited with code {result.returncode}")
                logger.warning(f"stderr: {result.stderr}")

            # Parse APKSlayer output
            # APKSlayer saves reports to its own reports directory
            # Check for findings.json in APKSlayer's reports dir
            apk_name_clean = Path(abs_apk_path).stem.split('_')[0]  # Extract package name
            apkslayer_reports = self.apkslayer_path / "reports" / apk_name_clean
            findings_json = apkslayer_reports / "findings.json"
            html_report = apkslayer_reports / "report.html"

            if findings_json.exists():
                logger.info(f"Found APKSlayer findings at: {findings_json}")
                with open(findings_json) as f:
                    findings = json.load(f)

                # Add HTML report path if it exists
                if html_report.exists():
                    findings['html_report'] = str(html_report)
                    logger.info(f"HTML report available at: {html_report}")

                return findings
            else:
                # Fallback: try to parse from stdout
                logger.warning("APKSlayer findings.json not found, parsing stdout")
                try:
                    # Extract vulnerability count from stdout
                    import re
                    vuln_match = re.search(r'Vulnerabilities found: (\d+)', result.stdout)
                    vuln_count = int(vuln_match.group(1)) if vuln_match else 0

                    return {
                        "vulnerabilities": [],
                        "vulnerability_count": vuln_count,
                        "raw_output": result.stdout,
                        "stderr": result.stderr,
                        "status": "completed" if vuln_count >= 0 else "partial"
                    }
                except Exception as e:
                    logger.error(f"Failed to parse APKSlayer output: {e}")
                    return {
                        "raw_output": result.stdout,
                        "stderr": result.stderr,
                        "status": "partial"
                    }

        except subprocess.TimeoutExpired:
            logger.error("APKSlayer timeout after 5 minutes")
            return {"error": "Timeout", "status": "incomplete"}
        except Exception as e:
            logger.error(f"APKSlayer execution failed: {str(e)}")
            raise

    def _download_apk(self, url_or_package: str, output_dir: Path, logger) -> str:
        """
        Download APK from various sources:
        - Google Play Store URL (https://play.google.com/store/apps/details?id=...)
        - Package ID (com.example.app) - requires apkeep installation
        - Direct APK download URL
        """
        logger.info(f"Attempting to download APK: {url_or_package}")

        success, apk_path, message = download_apk(url_or_package, output_dir)

        if not success:
            # Provide detailed error message
            logger.error(f"APK download failed: {message}")
            import re
            if re.match(r'^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$', url_or_package):
                error_msg = (
                    f"❌ Failed to auto-download APK for package: {url_or_package}\n\n"
                    f"Tried: Play Store → APKCombo → APKPure (all failed)\n"
                    f"Error: {message}\n\n"
                    f"💡 Alternative: Use a direct APK URL:\n"
                    f"1. Visit https://www.apkmirror.com/ or https://apkpure.com/\n"
                    f"2. Search for the app\n"
                    f"3. Download APK and get the direct URL\n"
                    f"4. Send: /analyze <apk-url>\n"
                )
                raise RuntimeError(error_msg)
            else:
                raise RuntimeError(f"Failed to download APK: {message}")

        logger.info(f"✅ {message}: {apk_path}")
        return str(apk_path)

    def _generate_mock_results(self, apk_name: str) -> Dict[str, Any]:
        """Generate mock results for dry run"""
        return {
            "apk_name": apk_name,
            "analysis_date": datetime.now().isoformat(),
            "package_name": "com.example.app",
            "version": "1.0.0",
            "min_sdk": 21,
            "target_sdk": 33,
            "vulnerabilities": [
                {
                    "id": "VULN-001",
                    "title": "Insecure WebView Configuration",
                    "severity": "high",
                    "category": "WebView Security",
                    "description": "WebView has JavaScript enabled without proper content security",
                    "location": "com.example.app.MainActivity",
                    "recommendation": "Disable JavaScript or implement Content Security Policy"
                },
                {
                    "id": "VULN-002",
                    "title": "Exported Activity without Permission",
                    "severity": "medium",
                    "category": "Component Security",
                    "description": "MainActivity is exported without permission check",
                    "location": "AndroidManifest.xml",
                    "recommendation": "Add permission requirement or set exported=false"
                },
                {
                    "id": "VULN-003",
                    "title": "Hardcoded API Key Detected",
                    "severity": "critical",
                    "category": "Data Leakage",
                    "description": "API key found in source code",
                    "location": "com.example.app.api.ApiClient",
                    "recommendation": "Move API keys to secure configuration"
                }
            ],
            "severity_counts": {
                "critical": 1,
                "high": 1,
                "medium": 1,
                "low": 0
            },
            "permissions": [
                "android.permission.INTERNET",
                "android.permission.READ_EXTERNAL_STORAGE",
                "android.permission.CAMERA"
            ],
            "exported_components": [
                {"type": "activity", "name": "MainActivity"},
                {"type": "receiver", "name": "PushNotificationReceiver"}
            ],
            "mode": "dry_run"
        }

    def report(self, run_id: str) -> Dict[str, Any]:
        """Generate APK analysis summary"""
        return {
            "run_id": run_id,
            "agent": self.name,
            "summary": "APKSlayer analysis completed"
        }
