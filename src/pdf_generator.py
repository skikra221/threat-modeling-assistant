import asyncio
import os
import sys
import multiprocessing
from datetime import datetime
from jinja2 import Environment, FileSystemLoader
from playwright.sync_api import sync_playwright

def _playwright_worker(html_content, output_queue):
    """
    Worker function to be run in a separate process.
    This avoids event loop conflicts with Streamlit.
    """
    try:
        # Fix for Windows loop policy in the new process
        if sys.platform == 'win32':
            asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
            
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.set_content(html_content)
            page.wait_for_load_state("networkidle")
            pdf_bytes = page.pdf(
                format="A4",
                print_background=True,
                margin={"top": "0mm", "right": "0mm", "bottom": "0mm", "left": "0mm"}
            )
            browser.close()
            output_queue.put(("success", pdf_bytes))
    except Exception as e:
        import traceback
        output_queue.put(("error", f"{str(e)}\n{traceback.format_exc()}"))

def generate_pdf_report(app_data, analysis):
    # 1. Process Metrics for the template
    threats = analysis.get("threats", [])
    scores = [t.get("score", 0) for t in threats]
    max_score = max(scores) if scores else 0
    
    if max_score > 100: global_level = "Critical"
    elif max_score > 60: global_level = "High"
    elif max_score > 25: global_level = "Medium"
    else: global_level = "Low"
    
    masvs_cats = set([t.get("masvs") for t in threats if t.get("masvs")])
    masvs_count = len(masvs_cats)
    
    metrics = {
        "max_score": max_score,
        "global_level": global_level,
        "masvs_count": masvs_count
    }
    
    # 2. Generate architecture HTML diagram for PDF
    from src.architecture_graph import build_architecture_html_for_pdf
    try:
        architecture_html = build_architecture_html_for_pdf(app_data)
    except Exception:
        architecture_html = '<div style="padding:12px;color:#64748B;font-style:italic;">Architecture diagram could not be generated.</div>'
    
    # 3. Render HTML with Jinja2
    env = Environment(loader=FileSystemLoader("templates"))
    template = env.get_template("pdf_report_template.html")
    
    html_content = template.render(
        app=app_data,
        analysis=analysis,
        metrics=metrics,
        architecture_html=architecture_html,
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M")
    )
    
    # 3. Generate PDF in a separate process to avoid loop conflicts
    output_queue = multiprocessing.Queue()
    process = multiprocessing.Process(
        target=_playwright_worker, 
        args=(html_content, output_queue)
    )
    
    process.start()
    
    # Wait for the result (with timeout)
    try:
        status, result = output_queue.get(timeout=60)
        process.join()
        
        if status == "success":
            return result
        else:
            raise Exception(f"Playwright Worker Error: {result}")
            
    except Exception as e:
        if process.is_alive():
            process.terminate()
        raise e
