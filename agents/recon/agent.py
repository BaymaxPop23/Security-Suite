"""Recon Agent - Attack Surface Discovery using EASD"""
import json
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List

from agents.base_agent import BaseAgent, RunResult
from core.schemas import Task
from core.telegram_notifier import notify_scan_complete


class ReconAgent(BaseAgent):
    """
    Recon Agent - External Attack Surface Discovery

    Uses EASD (External Attack Surface Discovery) tool to discover:
    - Subdomains via Certificate Transparency, DNS, passive sources
    - ASN & IP ranges via BGP/WHOIS
    - Port scanning (100+ ports)
    - Technology fingerprinting (60+ signatures)
    - Cloud assets (AWS S3, Azure Blob, GCP buckets)
    - GitHub intelligence & leaked secrets
    - Employee discovery & credential exposure
    """

    def __init__(self, dry_run: bool = False):
        super().__init__(name="recon", dry_run=dry_run)
        self.easd_path = Path(__file__).parent.parent.parent / "tools" / "EASD"

    def plan(self, context: Dict[str, Any]) -> List[Task]:
        """Not used in simplified architecture"""
        return []

    def run(self, task: Task, run_id: str) -> RunResult:
        """Execute reconnaissance using EASD"""
        logger, tracker, artifact_dir = self._setup_run(run_id, task.id)

        logger.log_task_start(task.id, task.type.value)
        start_time = datetime.now()

        try:
            # Extract domain/company from task inputs
            domain = task.inputs.get('domain')
            company = task.inputs.get('company')

            if not domain and not company:
                raise ValueError("No domain or company specified in task inputs")

            target = domain or company
            logger.info(f"Starting EASD reconnaissance for: {target}")

            # Prepare EASD command
            output_dir = artifact_dir / "easd_output"
            output_dir.mkdir(exist_ok=True)

            if self.dry_run:
                logger.info(f"[DRY RUN] Would run: easd discover --domain {target}")
                results = self._generate_mock_results(target)
            else:
                # Run EASD
                results = self._run_easd(target, output_dir, logger)

            # Save results as artifact
            results_file = self._save_json_artifact(
                results,
                "easd_results.json",
                artifact_dir
            )

            artifact = tracker.register(
                results_file,
                artifact_type="recon_report",
                task_id=task.id,
                metadata={
                    "target": target,
                    "subdomains_found": len(results.get('subdomains', [])),
                    "ips_found": len(results.get('ips', [])),
                    "ports_found": len(results.get('open_ports', [])),
                    "technologies": len(results.get('technologies', [])),
                }
            )

            logger.log_artifact(artifact.artifact_id, "recon_report", str(results_file))

            duration = (datetime.now() - start_time).total_seconds()
            logger.log_task_complete(task.id, duration, {
                "subdomains": len(results.get('subdomains', [])),
                "ips": len(results.get('ips', [])),
                "open_ports": len(results.get('open_ports', [])),
            })

            # Send Telegram notification with HTML report
            html_report_path = None
            if results.get('html_report'):
                html_report_path = Path(results['html_report'])

            try:
                notify_scan_complete(
                    target=target,
                    run_id=run_id,
                    html_report_path=html_report_path,
                    json_report_path=results_file,
                    results=results
                )
                logger.info("Telegram notification sent")
            except Exception as e:
                logger.warning(f"Failed to send Telegram notification: {e}")

            return RunResult(
                success=True,
                artifacts=[artifact.artifact_id],
                metadata={
                    "target": target,
                    "findings": results
                }
            )

        except Exception as e:
            logger.error(f"Recon failed: {str(e)}", task_id=task.id)
            return RunResult(success=False, error=str(e))

    def _run_easd(self, target: str, output_dir: Path, logger) -> Dict[str, Any]:
        """Run EASD tool"""
        logger.info(f"Launching EASD for {target}")

        # EASD needs to use its default results directory for session management
        # We'll let it use the default, then copy the results
        cmd = [
            "easd", "discover",
            "--domains", target,
            "--intensity", "normal"
            # Removed --passive-only to enable full active reconnaissance
            # including port scanning, subdomain enumeration, and tech fingerprinting
        ]

        logger.info(f"Command: {' '.join(cmd)}")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600  # 10 minute timeout
            )

            logger.info(f"EASD scan completed with exit code: {result.returncode}")

            if result.stdout:
                logger.info(f"EASD stdout: {result.stdout[:1000]}")
                # Parse session ID from stdout
                session_id = None
                for line in result.stdout.split('\n'):
                    if 'Session ID:' in line or 'session' in line.lower():
                        # Extract session ID from line
                        parts = line.split()
                        for part in parts:
                            if len(part) == 8 and part.isalnum():
                                session_id = part
                                break
                    if session_id:
                        break

            # If we couldn't find session from stdout, list sessions
            if not session_id:
                list_result = subprocess.run(
                    ["easd", "list"],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                logger.info(f"EASD list output: {list_result.stdout}")
                # Parse the most recent session
                lines = list_result.stdout.strip().split('\n')
                if len(lines) > 0 and lines[-1]:
                    # Usually the last line has the most recent session
                    session_id = lines[-1].split()[0] if lines[-1].split() else None

            if not session_id:
                logger.warning("Could not determine session ID")
                return {
                    "target": target,
                    "scan_completed": True,
                    "subdomains": [],
                    "message": "Scan completed but could not generate report"
                }

            logger.info(f"Using EASD session: {session_id}")

            # Generate JSON report
            json_report_file = output_dir / "report.json"
            json_result = subprocess.run(
                ["easd", "report", session_id, "--format", "json", "--output", str(json_report_file)],
                capture_output=True,
                text=True,
                timeout=60
            )

            if json_result.returncode != 0:
                logger.warning(f"JSON report generation failed: {json_result.stderr}")

            # Generate HTML report
            html_report_file = output_dir / "report.html"
            html_result = subprocess.run(
                ["easd", "report", session_id, "--format", "html", "--output", str(html_report_file)],
                capture_output=True,
                text=True,
                timeout=60
            )

            if html_result.returncode != 0:
                logger.warning(f"HTML report generation failed: {html_result.stderr}")

            # Prepare results data
            results_data = {
                "target": target,
                "scan_completed": True,
                "session_id": session_id,
                "subdomains": [],
                "ips": [],
                "ports": [],
                "technologies": []
            }

            # Parse JSON report
            if json_report_file.exists():
                try:
                    with open(json_report_file, 'r') as f:
                        report_data = json.load(f)
                        # EASD report structure varies, extract what we can
                        if isinstance(report_data, dict):
                            # Extract IPs
                            ip_addresses = report_data.get('ip_addresses', [])

                            # Extract unique hostnames/subdomains from IP addresses
                            all_hostnames = set()
                            all_ports = []

                            for ip in ip_addresses:
                                # Collect hostnames from each IP
                                hostnames = ip.get('hostnames', [])
                                all_hostnames.update(hostnames)

                                # Collect ports from each IP
                                ip_addr = ip.get('address', '')
                                for port in ip.get('ports', []):
                                    all_ports.append({
                                        "ip": ip_addr,
                                        "port": port.get('number'),
                                        "protocol": port.get('protocol', 'tcp'),
                                        "state": port.get('state', 'unknown'),
                                        "service": port.get('service', {}).get('name', 'unknown')
                                    })

                            results_data.update({
                                "subdomains": list(all_hostnames),
                                "ips": ip_addresses,
                                "ports": all_ports,
                                "technologies": report_data.get('technologies', report_data.get('tech_stack', [])),
                                "web_applications": report_data.get('web_applications', []),
                                "certificates": report_data.get('certificates', []),
                                "cloud_assets": report_data.get('cloud_assets', []),
                                "findings": report_data.get('findings', [])
                            })
                        logger.info(f"Parsed report: {len(results_data.get('subdomains', []))} subdomains, {len(results_data.get('ports', []))} ports")
                except Exception as e:
                    logger.warning(f"Failed to parse JSON report: {e}")

            # Record HTML report path
            if html_report_file.exists():
                results_data['html_report'] = str(html_report_file)
                logger.info(f"HTML report available at: {html_report_file}")

            return results_data

        except subprocess.TimeoutExpired:
            logger.error("EASD timeout after 10 minutes")
            return {"error": "Timeout", "status": "incomplete"}
        except Exception as e:
            logger.error(f"EASD execution failed: {str(e)}")
            raise

    def _generate_mock_results(self, target: str) -> Dict[str, Any]:
        """Generate mock results for dry run"""
        return {
            "target": target,
            "scan_date": datetime.now().isoformat(),
            "subdomains": [
                f"www.{target}",
                f"api.{target}",
                f"admin.{target}",
                f"mail.{target}",
                f"dev.{target}",
            ],
            "ips": [
                "192.0.2.1",
                "192.0.2.2",
            ],
            "open_ports": [
                {"ip": "192.0.2.1", "port": 80, "service": "http"},
                {"ip": "192.0.2.1", "port": 443, "service": "https"},
                {"ip": "192.0.2.2", "port": 22, "service": "ssh"},
            ],
            "technologies": [
                {"name": "nginx", "version": "1.21.0"},
                {"name": "React", "version": "18.0.0"},
                {"name": "Node.js", "version": "16.14.0"},
            ],
            "cloud_assets": [
                {"type": "s3", "bucket": f"{target.split('.')[0]}-backup"},
                {"type": "s3", "bucket": f"{target.split('.')[0]}-logs"},
            ],
            "vulnerabilities": [],
            "mode": "dry_run"
        }

    def report(self, run_id: str) -> Dict[str, Any]:
        """Generate recon run summary"""
        return {
            "run_id": run_id,
            "agent": self.name,
            "summary": "EASD reconnaissance completed"
        }
