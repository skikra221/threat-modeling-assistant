import os
import time
import json
import csv
from pathlib import Path

def run_single_evaluation(file_path):
    import time
    from src.parser import load_yaml, validate_app_data
    from src.rules_engine import analyze_application
    from src.scoring import score_threats, calculate_global_risk
    from src.rag_engine import enrich_threats_with_rag
    from src.remediation_roadmap import generate_remediation_roadmap, calculate_roadmap_metrics
    from src.report_generator import generate_report
    from src.pdf_generator import generate_pdf_report
    from src.evidence_pack import generate_evidence_pack
    from src.architecture_graph import build_mermaid_diagram

    start_time = time.perf_counter()
    
    path = Path(file_path)
    if not path.exists():
        return None
        
    input_type = "YAML"
    if path.suffix == ".apk":
        input_type = "APK"
        
    app_data = {}
    with open(path, "rb") as f:
        input_bytes = f.read()
        
    if input_type == "YAML":
        with open(path, "rb") as f:
            app_data = load_yaml(f)
            validate_app_data(app_data)
    else:
        from src.apk_parser import parse_apk_to_app_model
        with open(path, "rb") as f:
            app_data = parse_apk_to_app_model(f)
            
    analysis = analyze_application(app_data)
    analysis["threats"] = score_threats(analysis["threats"])
    analysis["threats"] = enrich_threats_with_rag(analysis["threats"], app_data)
    roadmap = generate_remediation_roadmap(analysis["threats"])
    analysis["roadmap"] = roadmap
    
    mermaid_diagram = build_mermaid_diagram(app_data)
    report_md = generate_report(app_data, analysis, mermaid_diagram)
    
    pdf_generated = False
    try:
        pdf_bytes = generate_pdf_report(app_data, analysis)
        if pdf_bytes:
            pdf_generated = True
    except Exception:
        pdf_bytes = None
        
    evidence_pack_generated = False
    try:
        ep = generate_evidence_pack(
            app_data=app_data,
            analysis=analysis,
            report_md=report_md,
            pdf_bytes=pdf_bytes,
            input_bytes=input_bytes,
            input_filename=path.name,
            input_type=input_type,
            architecture_mermaid=mermaid_diagram
        )
        if ep:
            evidence_pack_generated = True
    except Exception:
        pass
        
    end_time = time.perf_counter()
    
    threats = analysis.get("threats", [])
    
    critical_risks = sum(1 for t in threats if t.get("level", "").lower() in ["critique", "critical"])
    high_risks = sum(1 for t in threats if t.get("level", "").lower() in ["élevé", "high"])
    medium_risks = sum(1 for t in threats if t.get("level", "").lower() in ["moyen", "medium"])
    low_risks = sum(1 for t in threats if t.get("level", "").lower() in ["faible", "low"])
    
    max_score = max((t.get("score", 0) for t in threats), default=0)
    
    global_risk_level = "Faible"
    if max_score > 100: global_risk_level = "Critique"
    elif max_score > 60: global_risk_level = "Élevé"
    elif max_score > 25: global_risk_level = "Moyen"
    
    masvs_categories = set(str(t.get("masvs", "")).split(".")[0] for t in threats if t.get("masvs"))
    stride_categories = set(str(t.get("stride", "")).split("/")[0].strip().split(" ")[0] for t in threats if t.get("stride"))
    
    metrics = {
        "application_name": app_data.get("app_name", "Unknown"),
        "input_filename": path.name,
        "input_type": input_type,
        "analysis_time_seconds": round(end_time - start_time, 3),
        "threats_found": len(threats),
        "critical_risks": critical_risks,
        "high_risks": high_risks,
        "medium_risks": medium_risks,
        "low_risks": low_risks,
        "max_score": max_score,
        "global_risk_level": global_risk_level,
        "masvs_categories_covered": ", ".join(masvs_categories),
        "masvs_categories_count": len(masvs_categories),
        "stride_categories_covered": ", ".join(stride_categories),
        "stride_categories_count": len(stride_categories),
        "recommendations_count": len(roadmap),
        "missing_questions_count": len(analysis.get("missing", [])),
        "pdf_generated": pdf_generated,
        "markdown_generated": True,
        "evidence_pack_generated": evidence_pack_generated
    }
    
    return metrics

def run_all_evaluations(dataset_dir='data/evaluation_dataset'):
    path = Path(dataset_dir)
    results = []
    if not path.exists():
        return results
        
    for file in path.glob("*.*"):
        if file.suffix in [".yaml", ".yml", ".json", ".apk"]:
            res = run_single_evaluation(file)
            if res:
                results.append(res)
                
    return results

def export_results_csv(results, filepath):
    if not results: return
    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)

def export_results_json(results, filepath):
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

def export_results_md(results, filepath):
    if not results: return
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write("# Threat Modeling Assistant: Evaluation Results\n\n")
        
        f.write("## Overview\n")
        f.write(f"- Total Test Cases: {len(results)}\n")
        avg_time = sum(r['analysis_time_seconds'] for r in results) / len(results)
        f.write(f"- Average Analysis Time: {avg_time:.3f}s\n\n")
        
        f.write("## Metrics Table\n")
        header = "| App Name | Input | Time (s) | Threats | Critical | High | MASVS Cats | PDF Generated | Evidence Pack |\n"
        f.write(header)
        f.write("|---|---|---|---|---|---|---|---|---|\n")
        for r in results:
            f.write(f"| {r['application_name']} | {r['input_type']} | {r['analysis_time_seconds']} | {r['threats_found']} | {r['critical_risks']} | {r['high_risks']} | {r['masvs_categories_count']} | {r['pdf_generated']} | {r['evidence_pack_generated']} |\n")

def save_results(results, output_dir='evaluation_results'):
    out_path = Path(output_dir)
    out_path.mkdir(exist_ok=True)
    
    export_results_csv(results, out_path / "evaluation_results.csv")
    export_results_json(results, out_path / "evaluation_results.json")
    export_results_md(results, out_path / "evaluation_summary.md")
    
if __name__ == "__main__":
    print("Starting headless evaluation...")
    results = run_all_evaluations()
    if results:
        save_results(results)
        print(f"Evaluation complete. Saved results for {len(results)} cases in evaluation_results/")
    else:
        print("No test cases found.")
