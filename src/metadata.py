import hashlib
import json
from datetime import datetime
import platform
import sys

def compute_sha256_bytes(data: bytes) -> str:
    if not data: return ""
    return hashlib.sha256(data).hexdigest()

def compute_sha256_text(text: str) -> str:
    if not text: return ""
    return hashlib.sha256(text.encode('utf-8')).hexdigest()

def safe_json_dump(data) -> str:
    try:
        return json.dumps(data, indent=2, ensure_ascii=False)
    except Exception:
        return "{}"

def build_analysis_metadata(app_data, analysis, input_bytes=None, input_filename=None, input_type=None, report_md=None, pdf_bytes=None) -> dict:
    threat_count = len(analysis.get("threats", []))
    global_risk = "Unknown"
    max_score = 0
    if "threats" in analysis and len(analysis["threats"]) > 0:
        max_score = max(t.get("score", 0) for t in analysis["threats"])
        if max_score > 100: global_risk = "CRITIQUE"
        elif max_score > 60: global_risk = "ÉLEVÉ"
        elif max_score > 25: global_risk = "MOYEN"
        else: global_risk = "FAIBLE"
    
    masvs_categories = list(set(str(t.get("masvs", "")).split(".")[0] for t in analysis.get("threats", []) if t.get("masvs")))
    stride_categories = list(set(str(t.get("stride", "")).split("/")[0].strip().split(" ")[0] for t in analysis.get("threats", []) if t.get("stride")))
    
    high_risk_count = sum(1 for t in analysis.get("threats", []) if t.get("level") in ["Critique", "Élevé"])
    critical_risk_count = sum(1 for t in analysis.get("threats", []) if t.get("level") == "Critique" or t.get("score", 0) > 100)

    meta = {
        "tool_name": "Threat Modeling Assistant",
        "tool_version": "1.0.0",
        "analysis_timestamp": datetime.now().isoformat(),
        "input_type": input_type or app_data.get("app_type", "Unknown"),
        "input_filename": input_filename or "Unknown",
        "input_sha256": compute_sha256_bytes(input_bytes) if input_bytes else "Not provided",
        "app_name": app_data.get("app_name", "Unknown"),
        "app_type": app_data.get("app_type", "Unknown"),
        "threat_count": threat_count,
        "max_score": max_score,
        "global_risk_level": global_risk,
        "masvs_categories": masvs_categories,
        "stride_categories": stride_categories,
        "high_risk_count": high_risk_count,
        "critical_risk_count": critical_risk_count,
        "report_markdown_sha256": compute_sha256_text(report_md) if report_md else "",
        "evidence_pack_generated_at": datetime.now().isoformat()
    }
    if pdf_bytes:
        meta["report_pdf_sha256"] = compute_sha256_bytes(pdf_bytes)
        
    return meta
