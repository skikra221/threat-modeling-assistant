import io
import zipfile
import csv
import sys
import platform
from datetime import datetime
from src.metadata import compute_sha256_bytes, safe_json_dump, build_analysis_metadata

def dataframe_to_csv_bytes(rows, fieldnames):
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue().encode('utf-8')

def build_risk_register_exports(analysis):
    threats = analysis.get("threats", [])
    csv_columns = [
        "id", "threat", "stride", "asset", "entry_point", 
        "impact", "probability", "exposure", "score", 
        "level", "mitigation", "masvs", "status"
    ]
    rows = []
    for t in threats:
        row = {k: t.get(k, "") for k in csv_columns}
        rows.append(row)
    
    csv_bytes = dataframe_to_csv_bytes(rows, csv_columns)
    json_str = safe_json_dump(threats)
    return csv_bytes, json_str

def build_masvs_mapping(analysis):
    threats = analysis.get("threats", [])
    mapping = {}
    for t in threats:
        masvs = t.get("masvs")
        if not masvs: continue
        cat = str(masvs).split(".")[0]
        if cat not in mapping:
            mapping[cat] = []
        mapping[cat].append(t.get("id"))
    return mapping

def build_stride_summary(analysis):
    threats = analysis.get("threats", [])
    summary = {}
    for t in threats:
        stride_raw = t.get("stride", "")
        if not stride_raw: continue
        for part in stride_raw.split("/"):
            cat = part.strip()
            summary[cat] = summary.get(cat, 0) + 1
    return summary

def build_rag_export(analysis):
    threats = analysis.get("threats", [])
    rag_data_list = []
    for t in threats:
        if "rag_data" in t and t["rag_data"]:
            rag_data_list.append({
                "threat_id": t.get("id"),
                "rag_data": t["rag_data"]
            })
    return rag_data_list

def generate_analysis_log(app_data, analysis):
    log = []
    log.append(f"Analysis started at: {datetime.now().isoformat()}")
    log.append(f"App Name: {app_data.get('app_name', 'Unknown')}")
    log.append(f"App Type: {app_data.get('app_type', 'Unknown')}")
    log.append(f"Threats generated: {len(analysis.get('threats', []))}")
    return "\n".join(log)

def generate_evidence_pack(app_data, analysis, report_md, pdf_bytes=None, input_bytes=None, input_filename=None, input_type=None, architecture_mermaid=None, architecture_dot=None):
    zip_buffer = io.BytesIO()
    
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
        
        # 1. input/
        if input_bytes:
            safe_filename = input_filename or "original_input.bin"
            zip_file.writestr(f"input/{safe_filename}", input_bytes)
            zip_file.writestr("input/input_hash_sha256.txt", compute_sha256_bytes(input_bytes))
        else:
            zip_file.writestr("input/input_not_available.txt", "Original input bytes were not provided to the evidence packer.")
            
        if "apk_metadata" in app_data:
            zip_file.writestr("input/apk_metadata.json", safe_json_dump(app_data["apk_metadata"]))
            
        # 2. reports/
        zip_file.writestr("reports/threat_model_report.md", report_md)
        if pdf_bytes:
            zip_file.writestr("reports/threat_model_report.pdf", pdf_bytes)
        else:
            zip_file.writestr("reports/pdf_not_available.txt", "PDF generation was skipped or failed.")
            
        # 3. exports/
        csv_bytes, json_str = build_risk_register_exports(analysis)
        zip_file.writestr("exports/risk_register.csv", csv_bytes)
        zip_file.writestr("exports/risk_register.json", json_str)
        zip_file.writestr("exports/masvs_mapping.json", safe_json_dump(build_masvs_mapping(analysis)))
        zip_file.writestr("exports/stride_summary.json", safe_json_dump(build_stride_summary(analysis)))
        
        if "roadmap" in analysis and analysis["roadmap"]:
            zip_file.writestr("exports/remediation_roadmap.json", safe_json_dump(analysis["roadmap"]))
            
        rag_data = build_rag_export(analysis)
        if rag_data:
            zip_file.writestr("exports/rag_explanations.json", safe_json_dump(rag_data))
        else:
            zip_file.writestr("exports/rag_explanations.json", "[]")
            
        # 4. diagrams/
        if architecture_mermaid:
            zip_file.writestr("diagrams/architecture_diagram.mmd", architecture_mermaid)
        if architecture_dot:
            zip_file.writestr("diagrams/architecture_diagram.dot", architecture_dot)
            
        if not architecture_mermaid and not architecture_dot:
            zip_file.writestr("diagrams/diagram_not_available.txt", "No architecture diagrams were generated.")
            
        # 5. metadata/
        meta_dict = build_analysis_metadata(app_data, analysis, input_bytes, input_filename, input_type, report_md, pdf_bytes)
        zip_file.writestr("metadata/analysis_metadata.json", safe_json_dump(meta_dict))
        zip_file.writestr("metadata/tool_version.txt", meta_dict.get("tool_version", "1.0.0"))
        zip_file.writestr("metadata/timestamp.txt", meta_dict.get("analysis_timestamp", ""))
        
        env_str = f"Python version: {sys.version}\\nOperating system: {platform.platform()}\\nProject name: {meta_dict.get('tool_name')}\\nGeneration timestamp: {datetime.now().isoformat()}"
        zip_file.writestr("metadata/environment.txt", env_str)
        
        # 6. audit_trail/
        zip_file.writestr("audit_trail/analysis_log.txt", generate_analysis_log(app_data, analysis))
        
    return zip_buffer.getvalue()
