"""Report generation endpoints"""
from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
from pathlib import Path
import json
from typing import List, Dict, Any

from orchestrator.run_manager import RunManager

router = APIRouter()


@router.post("/reports/{run_id}/generate")
async def generate_report(run_id: str) -> dict:
    """Generate HTML report for a run"""
    try:
        run_manager = RunManager()
        report_path = run_manager.generate_final_report(run_id)

        return {
            "run_id": run_id,
            "report_path": report_path,
            "report_url": f"/api/reports/{run_id}/index"
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/reports")
async def list_reports() -> Dict[str, Any]:
    """List all EASD and APK analysis reports"""
    reports = []

    # Scan recon artifacts
    recon_dir = Path("artifacts/recon")
    if recon_dir.exists():
        for run_dir in recon_dir.iterdir():
            if run_dir.is_dir():
                easd_results = run_dir / "easd_results.json"
                if easd_results.exists():
                    try:
                        with open(easd_results, 'r') as f:
                            data = json.load(f)
                            # Check if HTML report exists
                            html_report = None
                            easd_output_dir = run_dir / "easd_output"
                            if easd_output_dir.exists():
                                html_file = easd_output_dir / "report.html"
                                if html_file.exists():
                                    html_report = str(html_file)

                            reports.append({
                                "type": "recon",
                                "run_id": run_dir.name,
                                "target": data.get('target', 'unknown'),
                                "subdomains": len(data.get('subdomains', [])),
                                "file": str(easd_results),
                                "html_report": html_report,
                                "timestamp": run_dir.stat().st_mtime
                            })
                    except:
                        pass

    # Scan APK artifacts
    apk_dir = Path("artifacts/apk_analyzer")
    if apk_dir.exists():
        for run_dir in apk_dir.iterdir():
            if run_dir.is_dir():
                apk_results = run_dir / "apkslayer_results.json"
                if apk_results.exists():
                    try:
                        with open(apk_results, 'r') as f:
                            data = json.load(f)
                            # APKSlayer uses 'findings' not 'vulnerabilities'
                            findings = data.get('findings', data.get('vulnerabilities', []))
                            apk_name = data.get('apk', data.get('apk_name', data.get('package', 'unknown')))

                            reports.append({
                                "type": "apk",
                                "run_id": run_dir.name,
                                "apk_name": apk_name,
                                "vulnerabilities": len(findings),
                                "total_findings": data.get('total_findings', len(findings)),
                                "file": str(apk_results),
                                "html_report": data.get('html_report'),  # APKSlayer HTML report path
                                "timestamp": run_dir.stat().st_mtime
                            })
                    except:
                        pass

    # Sort by timestamp descending
    reports.sort(key=lambda x: x.get('timestamp', 0), reverse=True)

    return {"reports": reports}


@router.get("/reports/{run_id}/html")
async def get_html_report(run_id: str):
    """Serve the EASD or APK HTML report"""
    # Try EASD report first
    recon_dir = Path("artifacts/recon") / run_id / "easd_output"
    if recon_dir.exists():
        html_file = recon_dir / "report.html"
        if html_file.exists():
            return FileResponse(html_file, media_type="text/html")

    # Try APK report
    apk_dir = Path("artifacts/apk_analyzer") / run_id
    if apk_dir.exists():
        apk_results = apk_dir / "apkslayer_results.json"
        if apk_results.exists():
            try:
                with open(apk_results, 'r') as f:
                    data = json.load(f)
                    html_report_path = data.get('html_report')
                    if html_report_path:
                        html_file = Path(html_report_path)
                        if html_file.exists():
                            return FileResponse(html_file, media_type="text/html")
            except:
                pass

    raise HTTPException(status_code=404, detail="HTML report not found")


@router.get("/reports/{run_id}/json")
async def get_json_report(run_id: str):
    """Download the JSON report"""
    # Look for JSON report in recon artifacts
    recon_dir = Path("artifacts/recon") / run_id

    if recon_dir.exists():
        json_file = recon_dir / "easd_results.json"
        if json_file.exists():
            return FileResponse(
                json_file,
                media_type="application/json",
                filename=f"easd_report_{run_id}.json"
            )

    raise HTTPException(status_code=404, detail="JSON report not found")


@router.get("/reports/{run_id}/index")
async def get_report(run_id: str):
    """Serve the HTML report (legacy endpoint)"""
    # Find report directory
    reports_dir = Path("reports")

    # Look for report with this run_id
    for report_dir in reports_dir.glob(f"*-{run_id}"):
        index_file = report_dir / "index.html"
        if index_file.exists():
            return FileResponse(index_file)

    raise HTTPException(status_code=404, detail="Report not found")
