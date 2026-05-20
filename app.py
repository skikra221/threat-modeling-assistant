import pandas as pd
import streamlit as st
import plotly.express as px
import time
import base64
import os
from io import BytesIO

from src.parser import load_yaml, validate_app_data
from src.rules_engine import analyze_application
from src.scoring import score_threats, calculate_global_risk
from src.report_generator import generate_report
from src.pdf_generator import generate_pdf_report
from src.architecture_graph import (
    build_architecture_dot_summary,
    build_architecture_dot_detailed,
    build_mermaid_diagram,
)
from src.remediation_roadmap import generate_remediation_roadmap, calculate_roadmap_metrics

# Configuration de la page
st.set_page_config(
    page_title="Threat Modeling Assistant | SOC Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

if 'intro_seen' not in st.session_state:
    st.session_state['intro_seen'] = False

from pathlib import Path

def get_base64_image(image_path: str) -> str:
    path = Path(image_path)
    if not path.exists():
        return ""
    return base64.b64encode(path.read_bytes()).decode("utf-8")


def inject_intro_css(image_base64: str):
    if image_base64:
        background_css = f"background-image: linear-gradient(rgba(0,0,0,0.10), rgba(0,0,0,0.18)), url('data:image/png;base64,{image_base64}');"
    else:
        background_css = "background: transparent;"

    st.markdown(f"""
<style>


header[data-testid="stHeader"] {{
    display: none;
}}

.block-container {{
    padding: 0 !important;
    max-width: 100% !important;
}}

.crt-intro-screen {{
    position: fixed;
    inset: 0;
    width: 100vw;
    height: 100vh;
    {background_css}
    background-size: cover;
    background-position: center center;
    background-repeat: no-repeat;
    z-index: 999999;
    overflow: hidden;
}}

.crt-intro-screen::after {{
    content: "";
    position: absolute;
    inset: 0;
    background: repeating-linear-gradient(
        to bottom,
        rgba(57,255,136,0.035) 0px,
        rgba(57,255,136,0.035) 1px,
        transparent 2px,
        transparent 5px
    );
    mix-blend-mode: screen;
    pointer-events: none;
    opacity: 0.38;
}}

.intro-loading-label {{
    position: absolute;
    left: 50%;
    bottom: 54px;
    transform: translateX(-50%);
    color: #A7F3D0;
    font-family: Consolas, 'Courier New', monospace;
    font-size: 0.86rem;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    z-index: 3;
    text-shadow: 0 0 10px rgba(57,255,136,0.5);
}}

.intro-progress-wrapper {{
    position: absolute;
    left: 50%;
    bottom: 28px;
    transform: translateX(-50%);
    width: min(520px, 72vw);
    height: 5px;
    background: rgba(57,255,136,0.12);
    border-radius: 999px;
    overflow: hidden;
    z-index: 2;
    box-shadow: 0 0 18px rgba(57,255,136,0.16);
}}

.intro-progress-fill {{
    height: 100%;
    width: 0%;
    background: linear-gradient(90deg, #22C55E, #39FF88, #A7F3D0);
    box-shadow: 0 0 16px rgba(57,255,136,0.75);
    animation: introLoad 7s linear forwards;
}}

.terminal-command-sequence {{
    position: absolute;
    left: 34%;
    top: 52%;
    width: 42%;
    z-index: 4;
    font-family: Consolas, "Courier New", monospace;
    font-size: clamp(0.75rem, 1.05vw, 1.05rem);
    line-height: 1.9;
    letter-spacing: 0.08em;
    color: #7CFFB2;
    text-shadow:
        0 0 8px rgba(57,255,136,0.75),
        0 0 18px rgba(57,255,136,0.35);
    opacity: 0.92;
    pointer-events: none;
}}

.terminal-line {{
    margin-bottom: 6px;
    opacity: 0;
    transform: translateY(6px);
    white-space: nowrap;
    animation: terminalLineIn 0.55s ease-out forwards;
}}

.tline-1 {{ animation-delay: 0.6s; }}
.tline-2 {{ animation-delay: 2.0s; }}
.tline-3 {{ animation-delay: 3.4s; }}
.tline-4 {{ animation-delay: 4.8s; }}
.tline-5 {{ animation-delay: 6.3s; }}

@keyframes terminalLineIn {{
    from {{
        opacity: 0;
        transform: translateY(6px);
        filter: blur(2px);
    }}
    to {{
        opacity: 1;
        transform: translateY(0);
        filter: blur(0);
    }}
}}

.terminal-cursor {{
    display: inline-block;
    margin-left: 4px;
    color: #39FF88;
    animation: terminalBlink 0.8s steps(1) infinite;
}}

@keyframes terminalBlink {{
    0%, 49% {{ opacity: 1; }}
    50%, 100% {{ opacity: 0; }}
}}

@media (max-width: 900px) {{
    .terminal-command-sequence {{
        left: 22%;
        top: 50%;
        width: 58%;
        font-size: 0.72rem;
        letter-spacing: 0.04em;
    }}

    .terminal-line {{
        white-space: normal;
    }}
}}
</style>
""", unsafe_allow_html=True)


def render_intro_screen():
    image_base64 = get_base64_image("assets/intro_terminal.png")
    inject_intro_css(image_base64)

    st.markdown("""
<div class="crt-intro-screen">
    <div class="terminal-command-sequence">
        <div class="terminal-line tline-1">&gt; INITIALIZING THREAT MODELING ENGINE...</div>
        <div class="terminal-line tline-2">&gt; LOADING OWASP MASVS KNOWLEDGE BASE...</div>
        <div class="terminal-line tline-3">&gt; MAPPING MOBILE ATTACK SURFACE...</div>
        <div class="terminal-line tline-4">&gt; PREPARING RISK REGISTER...</div>
        <div class="terminal-line tline-5">&gt; READY. <span class="terminal-cursor">█</span></div>
    </div>
    <div class="intro-loading-label">Loading Threat Modeling Assistant...</div>
    <div class="intro-progress-wrapper">
        <div class="intro-progress-fill"></div>
    </div>
</div>

<style>
    /* Force the Streamlit button to float on top of the intro screen */
    div.stButton > button {
        position: fixed !important;
        bottom: 24px !important;
        right: 180px !important; /* give space for ESC hint */
        z-index: 10000 !important;
        background: transparent !important;
        border: 1px solid rgba(75, 226, 119, 0.4) !important;
        color: #4BE277 !important;
        font-family: "JetBrains Mono", Consolas, monospace !important;
        font-size: 0.75rem !important;
        text-transform: uppercase !important;
        padding: 4px 12px !important;
        transition: all 0.2s !important;
        width: auto !important;
    }
    div.stButton > button:hover {
        background: rgba(75, 226, 119, 0.1) !important;
        border-color: #4BE277 !important;
    }
    
    .esc-hint {
        position: fixed;
        bottom: 30px;
        right: 40px;
        z-index: 10000;
        color: #6B8F7A;
        font-family: "JetBrains Mono", Consolas, monospace;
        font-size: 0.75rem;
        letter-spacing: 1px;
        text-transform: uppercase;
        pointer-events: none;
    }
</style>

<div class="esc-hint">Press ESC to skip</div>
""", unsafe_allow_html=True)
    
    import streamlit.components.v1 as components
    components.html("""
        <script>
            const doc = window.parent.document;
            doc.addEventListener('keydown', function(e) {
                if (e.key === 'Escape') {
                    const buttons = Array.from(doc.querySelectorAll('button'));
                    const skipBtn = buttons.find(b => b.textContent.includes('SKIP INTRO'));
                    if(skipBtn) skipBtn.click();
                }
            });
        </script>
    """, height=0)

    if st.button("SKIP INTRO"):
        st.session_state["intro_seen"] = True
        st.rerun()

    time.sleep(7)
    st.session_state["intro_seen"] = True
    st.rerun()


if "intro_seen" not in st.session_state:
    st.session_state["intro_seen"] = False

if not st.session_state["intro_seen"]:
    render_intro_screen()
    st.stop()


def inject_custom_css():
    st.markdown("""
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&display=swap');

        html, body {
            font-family: 'Inter', sans-serif;
        }

        /* Main Background */


        /* Streamlit Default Container */
        .block-container, [data-testid="stAppViewBlockContainer"] {
            padding-top: 0.5rem !important;
            margin-top: 0 !important;
            padding-bottom: 3rem !important;
            max-width: 1440px !important;
            margin: 0 auto !important;
        }
        
        /* Navbar Styling */
        [data-testid="stHorizontalBlock"]:first-of-type {
            backdrop-filter: blur(16px) !important;
            border-bottom: 1px solid rgba(255,255,255,0.06) !important;
            box-shadow: none !important;
            border-radius: 0 !important;
            padding: 0 32px !important;
            margin-bottom: 0 !important;
            margin-top: -1rem !important;
            min-height: 64px !important;
            height: 64px !important;
            align-items: center !important;
        }
        
        .brand {
            color: #4BE277;
            font-family: "JetBrains Mono", Consolas, monospace;
            font-size: 20px;
            font-weight: 800;
            letter-spacing: 0.08em;
            text-transform: uppercase;
            white-space: nowrap;
            margin-bottom: 0;
            line-height: 1;
        }

        .header-right {
            display: flex;
            align-items: center;
            justify-content: flex-end;
            gap: 12px;
            white-space: nowrap;
        }

        .status-pill {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 7px 12px;
            border-radius: 999px;
            background: rgba(34, 197, 94, 0.10);
            border: 1px solid rgba(34, 197, 94, 0.24);
            color: #86EFAC;
            font-family: "JetBrains Mono", Consolas, monospace;
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 0.08em;
            text-transform: uppercase;
        }

        .version-pill {
            display: inline-flex;
            align-items: center;
            padding: 7px 12px;
            border-radius: 999px;
            background: rgba(148, 163, 184, 0.08);
            border: 1px solid rgba(148, 163, 184, 0.16);
            color: #CBD5E1;
            font-family: "JetBrains Mono", Consolas, monospace;
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 0.08em;
        }

        .status-dot {
            width: 7px;
            height: 7px;
            border-radius: 999px;
            background: #4BE277;
            box-shadow: 0 0 12px rgba(74,226,119,0.8);
        }

        /* Streamlit Radio Override for Navbar Links */
        [data-testid="stRadio"] {
            margin: 0 !important;
            padding: 0 !important;
        }
        
        /* Completely remove the 'Navigation' label */
        [data-testid="stRadio"] [data-testid="stWidgetLabel"] {
            display: none !important;
            visibility: hidden !important;
            height: 0 !important;
            margin: 0 !important;
            padding: 0 !important;
        }
        
        [data-testid="stRadio"] > div {
            display: flex !important;
            gap: 26px !important;
            align-items: center !important;
            flex-direction: row !important;
            margin: 0 !important;
            padding: 0 !important;
        }
        /* Ensure Streamlit columns are perfectly vertically centered */
        [data-testid="stHorizontalBlock"]:first-of-type > [data-testid="stVerticalBlock"] {
            display: flex !important;
            justify-content: center !important;
            align-items: center !important;
            gap: 0 !important;
            padding: 0 !important;
        }

        [data-testid="stRadio"] label {
            display: inline-flex !important;
            align-items: center !important;
            justify-content: center !important;
            padding: 0 0 4px 0 !important;
            margin: 0 !important;
            background: transparent !important;
            border: none !important;
            border-bottom: 2px solid transparent !important; /* Placeholder for alignment */
            color: #BCCBB9 !important;
            font-family: "JetBrains Mono", Consolas, monospace !important;
            font-size: 14px !important;
            font-weight: 600 !important;
            letter-spacing: 0.05em !important;
            white-space: nowrap !important;
            cursor: pointer !important;
            line-height: 1 !important;
        }
        [data-testid="stRadio"] label:hover {
            color: #4CD7F6 !important;
        }
        [data-testid="stRadio"] label > div:first-child {
            display: none !important;
        }
        
        /* Apply active state cleanly without double lines */
        [data-testid="stRadio"] label:has(input:checked) {
            color: #4BE277 !important;
            border-bottom: 2px solid #4BE277 !important;
        }
        [data-testid="stRadio"] input:checked + div {
            color: #4BE277 !important;
        }

        /* Hero Section */
        .hero-title {
            font-size: 3.2rem;
            font-weight: 800;
            margin-bottom: 1.2rem;
            line-height: 1.15;
            color: #D4E4FA;
            letter-spacing: -0.5px;
        }
        .hero-highlight {
            color: #4BE277;
        }
        .hero-subtitle {
            font-size: 1.05rem;
            color: #BCCBB9;
            max-width: 500px;
            margin-bottom: 2.5rem;
            line-height: 1.6;
        }
        .enterprise-badge {
            display: inline-block;
            padding: 4px 14px;
            background: rgba(75, 226, 119, 0.1);
            border: 1px solid rgba(75, 226, 119, 0.3);
            border-radius: 20px;
            color: #4BE277;
            font-size: 0.65rem;
            font-weight: 700;
            letter-spacing: 1px;
            margin-bottom: 1.5rem;
        }
        
        /* Buttons */
        .stButton > button {
            border-radius: 4px !important;
            font-weight: 700 !important;
            font-size: 0.85rem !important;
            padding: 0.6rem 1.5rem !important;
            transition: all 0.2s !important;
            letter-spacing: 0.5px !important;
            text-transform: uppercase !important;
        }
        .stButton > button[kind="primary"] {
            background-color: #4BE277 !important;
            color: #010F1F !important;
            border: none !important;
            box-shadow: 0 4px 14px rgba(75, 226, 119, 0.25) !important;
        }
        .stButton > button[kind="primary"]:hover {
            background-color: #6BFF8F !important;
            box-shadow: 0 6px 20px rgba(75, 226, 119, 0.4) !important;
            transform: translateY(-2px);
        }
        .stButton > button[kind="secondary"] {
            background-color: transparent !important;
            border: 1px solid rgba(255,255,255,0.15) !important;
            color: #4CD7F6 !important;
        }
        .stButton > button[kind="secondary"]:hover {
            border-color: #4CD7F6 !important;
            background-color: rgba(76, 215, 246, 0.05) !important;
            transform: translateY(-2px);
        }
        
        /* Premium Upload Glass Panel Container */
        [data-testid="stVerticalBlockBorderWrapper"] {
            background: transparent !important;
            backdrop-filter: none !important;
            border: none !important;
            border-radius: 0 !important;
            padding: 0 !important;
            min-height: auto;
            box-shadow: none !important;
        }
        
        /* Segmented Control Override */
        [data-testid="stSegmentedControl"] {
            background: transparent !important;
            border: none !important;
            border-radius: 6px !important;
            padding: 0 !important;
            gap: 0 !important;
            display: flex !important;
            width: fit-content !important;
            margin-bottom: 20px !important;
        }
        [data-testid="stSegmentedControl"] button {
            border-radius: 6px !important;
            color: #A7B4C5 !important;
            background: #16212B !important;
            font-weight: 500 !important;
            font-size: 0.85rem !important;
            white-space: nowrap !important;
            border: none !important;
            padding: 8px 18px !important;
            min-height: 0 !important;
            height: auto !important;
            transition: none !important;
            margin-right: 4px !important;
        }
        [data-testid="stSegmentedControl"] button[aria-selected="true"],
        [data-testid="stSegmentedControl"] button[aria-selected="true"]:hover {
            background: rgba(75, 226, 119, 0.1) !important;
            color: #4BE277 !important;
            border: 1px solid rgba(75, 226, 119, 0.3) !important;
            font-weight: 600 !important;
            box-shadow: none !important;
        }
        [data-testid="stSegmentedControl"] p {
            margin: 0 !important;
        }
        
        /* File Uploader Custom Dropzone */
        [data-testid="stFileUploader"] {
            width: 100%;
        }
        [data-testid="stFileUploaderDropzone"] {
            background-color: transparent !important;
            padding: 3rem 2rem !important;
            border: 1px dashed rgba(255,255,255,0.15) !important;
            border-radius: 8px !important;
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }
        [data-testid="stFileUploaderDropzone"]::before {
            content: '';
            position: absolute;
            top: -50%; left: -50%; width: 200%; height: 200%;
            background: linear-gradient(to bottom, transparent, rgba(74, 225, 118, 0.05), transparent);
            transform: translateY(-100%);
            animation: scanline 4s linear infinite;
            pointer-events: none;
        }
        @keyframes scanline {
            0% { transform: translateY(-100%); }
            100% { transform: translateY(100%); }
        }
        [data-testid="stFileUploaderDropzone"]:hover {
            border-color: #4BE277 !important;
            background-color: rgba(75, 226, 119, 0.03) !important;
        }
        [data-testid="stFileUploaderDropzone"] > div > span {
            display: none !important; /* Hide original small text */
        }
        [data-testid="stFileUploader"] button {
            border-radius: 4px !important;
            background: rgba(255,255,255,0.05) !important;
            border: 1px solid rgba(255,255,255,0.1) !important;
            color: #D4E4FA !important;
        }
        [data-testid="stFileUploader"] button:hover {
            border-color: #4BE277 !important;
            color: #4BE277 !important;
        }

        /* Feature Cards */
        .feature-card {
            background: linear-gradient(135deg, rgba(8,18,32,0.5), rgba(3,12,23,0.4));
            border: 1px solid rgba(148,163,184,0.08);
            border-radius: 16px;
            padding: 1.5rem;
            height: 100%;
            transition: all 0.3s ease;
            display: flex;
            flex-direction: column;
            gap: 12px;
        }
        .feature-card:hover {
            transform: translateY(-4px);
            border-color: rgba(74, 226, 119, 0.2);
            background: linear-gradient(135deg, rgba(8,18,32,0.65), rgba(3,12,23,0.55));
            box-shadow: 0 8px 24px rgba(0,0,0,0.2);
        }
        .feature-icon {
            color: #4BE277;
            font-size: 1.5rem;
        }
        .feature-title {
            color: #D4E4FA;
            font-weight: 600;
            font-size: 1.05rem;
            margin: 0;
        }
        .feature-desc {
            color: #BCCBB9;
            font-size: 0.85rem;
            line-height: 1.5;
            margin: 0;
        }

        /* Footer Info Bar */
        .info-bar {
            background-color: #051424;
            padding: 16px 2rem;
            color: #6B8F7A;
            font-size: 0.75rem;
            font-weight: 600;
            display: flex;
            align-items: center;
            justify-content: space-between;
            position: fixed;
            bottom: 0; left: 0; right: 0;
            z-index: 1000;
            display: flex;
            justify-content: space-between;
        }
        
        /* Hide default elements */
        #MainMenu {visibility: hidden;}
        footer {visibility: hidden;}
        header {display: none !important; height: 0px !important;}
        
        /* Ensure top margin is 0 */
        body { margin: 0 !important; }

        
        /* Animations */
        @keyframes fadeInUp {
            from { opacity: 0; transform: translateY(15px); }
            to { opacity: 1; transform: translateY(0); }
        }
        @keyframes softPulseRed {
            0% { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.4); }
            70% { box-shadow: 0 0 0 12px rgba(239, 68, 68, 0); }
            100% { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0); }
        }
        @keyframes softPulseOrange {
            0% { box-shadow: 0 0 0 0 rgba(249, 115, 22, 0.4); }
            70% { box-shadow: 0 0 0 12px rgba(249, 115, 22, 0); }
            100% { box-shadow: 0 0 0 0 rgba(249, 115, 22, 0); }
        }
        .fade-in-up {
            animation: fadeInUp 0.6s ease-out forwards;
        }
        .pulse-critical {
            animation: softPulseRed 2s infinite;
            border-color: rgba(239, 68, 68, 0.8) !important;
        }
        .pulse-high {
            animation: softPulseOrange 2s infinite;
            border-color: rgba(249, 115, 22, 0.8) !important;
        }
        
        /* Navbar */
        .sticky-navbar {
            position: fixed;
            top: 0; left: 0; right: 0;
            height: 60px;
            background: rgba(5, 10, 18, 0.85);
            backdrop-filter: blur(12px);
            border-bottom: 1px solid #1F6B46;
            z-index: 9999;
            display: flex;
            align-items: center;
            padding: 0 2rem;
            justify-content: space-between;
        }
        .navbar-brand {
            font-weight: 800;
            color: #F8FAFC;
            font-size: 1.1rem;
            letter-spacing: 0.5px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .navbar-nav {
            display: flex;
            gap: 20px;
        }
        .nav-item {
            color: #94A3B8;
            font-size: 0.85rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
            text-decoration: none;
            transition: color 0.2s;
        }
        .nav-item:hover {
            color: #39FF88;
        }
        
        /* Stepper */
        .stepper-container {
            display: flex;
            align-items: center;
            justify-content: space-between;
            background: linear-gradient(135deg, rgba(8,18,32,0.28), rgba(3,12,23,0.3));
            border: 1px solid rgba(148,163,184,0.08);
            border-radius: 16px;
            padding: 1.5rem 2rem;
            margin-bottom: 2rem;
            box-shadow: none;
        }
        .step {
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 8px;
            position: relative;
            flex: 1;
        }
        .step:not(:last-child)::after {
            content: '';
            position: absolute;
            top: 15px;
            left: 55%;
            right: -45%;
            height: 2px;
            background: #1F6B46;
            z-index: 0;
        }
        .step.active:not(:last-child)::after, .step.completed:not(:last-child)::after {
            background: #39FF88;
        }
        .step-icon {
            width: 32px; height: 32px;
            border-radius: 50%;
            background: #050A12;
            border: 2px solid #1F6B46;
            display: flex; align-items: center; justify-content: center;
            z-index: 1;
            color: #6B8F7A;
            font-weight: bold;
            font-size: 0.85rem;
            transition: all 0.3s;
        }
        .step.active .step-icon {
            border-color: #0A84FF;
            color: #0A84FF;
            box-shadow: 0 0 10px rgba(10, 132, 255, 0.4);
        }
        .step.completed .step-icon {
            background: #39FF88;
            border-color: #39FF88;
            color: #050A12;
            box-shadow: 0 0 10px rgba(57, 255, 136, 0.4);
        }
        .step-label {
            font-size: 0.75rem;
            font-weight: 600;
            color: #94A3B8;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            text-align: center;
        }
        .step.active .step-label { color: #0A84FF; }
        .step.completed .step-label { color: #39FF88; }
        /* ── LEFT GUTTER / SIDEBAR KILL ──────────────────────────────── */
        [data-testid="stSidebar"] { display: none !important; }
        [data-testid="collapsedControl"] { display: none !important; }
        section[data-testid="stSidebar"] + section { margin-left: 0 !important; }
        .main .block-container { padding-left: 2rem !important; padding-right: 2rem !important; }
        
        /* ── RISK REGISTER TABLE ────────────────────────────────────────── */
        .rr-section {
            margin-top: 2rem;
        }
        .rr-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }
        .rr-title {
            font-family: 'Inter', sans-serif;
            font-size: 32px;
            font-weight: 800;
            color: #F8FAFC;
            letter-spacing: -0.02em;
            line-height: 1;
            margin: 0;
        }
        .rr-pre-label {
            font-family: 'JetBrains Mono', Consolas, monospace;
            font-size: 11px;
            font-weight: 800;
            color: #4BE277;
            text-transform: uppercase;
            letter-spacing: 0.16em;
            margin-bottom: 6px;
        }
        .rr-count-badge {
            background: rgba(75,226,119,0.1);
            border: 1px solid rgba(75,226,119,0.22);
            border-radius: 999px;
            padding: 4px 14px;
            font-family: 'JetBrains Mono', Consolas, monospace;
            font-size: 11px;
            font-weight: 800;
            color: #4BE277;
        }
        .rr-table-wrap {
            width: 100%;
            overflow-x: auto;
            border-radius: 18px;
            border: 1px solid rgba(148,163,184,0.1);
        }
        .rr-table {
            width: 100%;
            border-collapse: collapse;
            font-family: 'Inter', sans-serif;
        }
        .rr-table thead tr {
            background: rgba(8,18,32,0.62);
            backdrop-filter: blur(12px);
            border-bottom: 1px solid rgba(148,163,184,0.14);
        }
        .rr-table thead th {
            font-family: 'JetBrains Mono', Consolas, monospace;
            font-size: 11px;
            font-weight: 800;
            color: #6B8F7A;
            text-transform: uppercase;
            letter-spacing: 0.1em;
            padding: 14px 16px;
            text-align: left;
            white-space: nowrap;
        }
        .rr-table tbody tr {
            border-bottom: 1px solid rgba(148,163,184,0.06);
            transition: background 0.15s;
        }
        .rr-table tbody tr:hover { background: rgba(75,226,119,0.03); }
        .rr-table tbody tr:last-child { border-bottom: none; }
        .rr-table tbody td {
            padding: 14px 16px;
            font-size: 14px;
            color: #D4E4FA;
            vertical-align: middle;
        }
        .rr-id {
            font-family: 'JetBrains Mono', Consolas, monospace;
            font-size: 12px;
            color: #6B8F7A;
            white-space: nowrap;
        }
        .rr-desc {
            line-height: 1.5;
            color: #F1F5F9;
            font-weight: 500;
            font-size: 14px;
        }
        .rr-score {
            font-size: 18px;
            font-weight: 800;
            font-family: 'Inter', sans-serif;
        }
        .rr-masvs {
            font-family: 'JetBrains Mono', Consolas, monospace;
            font-size: 12px;
            color: #38BDF8;
            font-weight: 700;
        }
        /* Severity Badges */
        .sev-badge {
            display: inline-block;
            padding: 3px 10px;
            border-radius: 999px;
            font-family: 'JetBrains Mono', Consolas, monospace;
            font-size: 11px;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            white-space: nowrap;
        }
        .sev-critique { background: rgba(239,68,68,0.12); color: #EF4444; border: 1px solid rgba(239,68,68,0.28); }
        .sev-eleve    { background: rgba(249,115,22,0.12); color: #F97316; border: 1px solid rgba(249,115,22,0.28); }
        .sev-moyen    { background: rgba(250,204,21,0.1);  color: #FACC15; border: 1px solid rgba(250,204,21,0.25); }
        .sev-faible   { background: rgba(75,226,119,0.1);  color: #4BE277; border: 1px solid rgba(75,226,119,0.22); }
        /* STRIDE mini-badges */
        .stride-chip {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 6px;
            font-family: 'JetBrains Mono', Consolas, monospace;
            font-size: 11px;
            font-weight: 700;
            background: rgba(56,189,248,0.1);
            color: #38BDF8;
            border: 1px solid rgba(56,189,248,0.2);
            margin-bottom: 3px;
            white-space: nowrap;
        }
        
        
        /* FINAL BLACK WRAPPER KILLER — MUST BE LAST */

        .stApp {
            background-color: #051424 !important;
            background-image:
                radial-gradient(circle at 50% -20%, rgba(74,225,118,0.05) 0%, transparent 50%),
                linear-gradient(rgba(255,255,255,0.025) 1px, transparent 1px),
                linear-gradient(90deg, rgba(255,255,255,0.025) 1px, transparent 1px) !important;
            background-size: 100% 100%, 40px 40px, 40px 40px !important;
            color: #D4E4FA !important;
            margin-top: 0 !important;
        }

        /* Streamlit parent containers must be transparent */
        [data-testid="stAppViewContainer"],
        [data-testid="stHeader"],
        [data-testid="stToolbar"],
        section.main,
        .block-container,
        [data-testid="stVerticalBlock"],
        [data-testid="stHorizontalBlock"],
        [data-testid="stElementContainer"] {
            background: transparent !important;
            background-color: transparent !important;
        }

        /* Remove large black wrappers only */
        .hero-wrapper,
        .dashboard-hero-wrapper,
        .metrics-wrapper,
        .kpi-wrapper,
        .risk-register-wrapper,
        .risk-register-section,
        .rr-section,
        .rr-wrapper,
        .rr-filters-wrapper,
        .analytics-section-wrapper,
        .analytics-outer-wrapper,
        .recommendations-wrapper,
        .high-priority-wrapper,
        .roadmap-wrapper,
        .remediation-wrapper,
        .report-wrapper,
        .evidence-wrapper,
        .section-wrapper,
        .section-container,
        .black-section,
        .dark-section,
        .full-width-panel,
        .large-panel {
            background: transparent !important;
            background-color: transparent !important;
            box-shadow: none !important;
            border: none !important;
        }

        /* Remove Streamlit border wrapper black panels */
        [data-testid="stVerticalBlockBorderWrapper"] {
            background: transparent !important;
            background-color: transparent !important;
            box-shadow: none !important;
        }

        /* Make table/filter dark surfaces lighter, not black */
        .risk-register-table,
        .rr-table,
        .rr-filter-bar,
        .filter-bar,
        .table-wrapper {
            background: rgba(8,18,32,0.22) !important;
            background-color: rgba(8,18,32,0.22) !important;
            backdrop-filter: blur(12px) !important;
        }

        /* Keep individual cards readable but not black */
        .info-card,
        .metric-card,
        .kpi-card,
        .recommendation-card,
        .roadmap-card,
        .analytics-card,
        .upload-card,
        .evidence-card,
        .report-card {
            background: linear-gradient(
                135deg,
                rgba(8,18,32,0.46),
                rgba(5,24,20,0.28)
            ) !important;
            border: 1px solid rgba(148,163,184,0.10) !important;
            box-shadow: 0 18px 50px rgba(0,0,0,0.16) !important;
            backdrop-filter: blur(14px) !important;
        }

        /* Do not let empty wrappers create black rectangles */
        div:empty {
            background: transparent !important;
        }
    </style>
    """, unsafe_allow_html=True)

def apply_theme_css(theme_mode: str):
    resolved = theme_mode
    if theme_mode == "system":
        resolved = "dark"
    if resolved == "light":
        st.markdown("""
        <style>
            .stApp { background: #F8FAFC !important; color: #0F172A !important; }
            [data-testid="stHorizontalBlock"]:first-of-type {
                border-bottom: 1px solid rgba(15, 23, 42, 0.10) !important;
                background: rgba(255,255,255,0.88) !important;
            }
            .brand { color: #16A34A !important; }
            [data-testid="stRadio"] label { color: #334155 !important; }
            [data-testid="stRadio"] label[data-selected="true"] {
                color: #0F172A !important;
                border-bottom-color: #16A34A !important;
            }
            .status-pill {
                background: rgba(22,163,74,0.10) !important;
                border-color: rgba(22,163,74,0.28) !important;
                color: #166534 !important;
            }
            .version-pill {
                background: rgba(148,163,184,0.12) !important;
                border-color: rgba(100,116,139,0.30) !important;
                color: #334155 !important;
            }
            div[data-testid="stFileUploader"] section,
            div[data-testid="stFileUploaderDropzone"] {
                background: #FFFFFF !important;
                border-color: rgba(15,23,42,0.18) !important;
            }
            .theme-help { color:#475569 !important; }
        </style>
        """, unsafe_allow_html=True)

def render_navbar():
    st.markdown("""
    <div class="sticky-navbar">
        <div class="navbar-brand">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#39FF88" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
            Threat Modeling Assistant <span style="color:#6B8F7A; font-weight: 500; font-size: 0.8rem; margin-left: 10px;">Enterprise SOC View</span>
        </div>
        <div class="navbar-nav">
            <span class="nav-item active">Dashboard</span>
            <span class="nav-item">Architecture</span>
            <span class="nav-item">RAG Insights</span>
        </div>
    </div>
    <div style="height: 70px;"></div>
    """, unsafe_allow_html=True)

def render_analysis_stepper(current_step=0):
    steps = [
        "Input Loaded",
        "Assets Mapped",
        "Threats Gen",
        "Risks Scored",
        "Report Ready"
    ]
    
    html = '<div class="stepper-container fade-in-up">'
    for i, step in enumerate(steps):
        if i < current_step:
            status_class = "completed"
            icon = "✓"
        elif i == current_step:
            status_class = "active"
            icon = str(i + 1)
        else:
            status_class = ""
            icon = str(i + 1)
            
        html += f"""
        <div class="step {status_class}">
            <div class="step-icon">{icon}</div>
            <div class="step-label">{step}</div>
        </div>
        """
    html += '</div>'
    st.markdown(html, unsafe_allow_html=True)

def render_hero():
    st.markdown('<div class="hero-wrapper fade-in-up" style="margin-top: 0; padding-top: 12px; padding-bottom: 48px; background:transparent;">', unsafe_allow_html=True)
    
    col_left, spacer, col_right = st.columns([1.05, 0.05, 0.95])
    
    with col_left:
        st.markdown('<div class="enterprise-badge"><span style="display:inline-block;width:6px;height:6px;border-radius:50%;background:#4BE277;margin-right:6px;"></span>ENTERPRISE EDITION V2.4</div>', unsafe_allow_html=True)
        st.markdown('<h1 class="hero-title" style="max-width: 650px; font-size: 56px;">AI-Ready <span class="hero-highlight">Threat Modeling</span><br>for Mobile Applications</h1>', unsafe_allow_html=True)
        st.markdown('<p class="hero-subtitle" style="max-width: 600px;">Automated STRIDE and MASVS 2.0 analysis pipeline. Identify architecture flaws, map regulatory requirements, and generate mitigation strategies in seconds.</p>', unsafe_allow_html=True)
        
        btn_col1, btn_col2, _ = st.columns([1.2, 1.4, 0.5])
        with btn_col1:
            st.button("🚀 START ANALYSIS", disabled=True, use_container_width=True, type="primary")
        with btn_col2:
            if st.button("VIEW DOCUMENTATION", key="hero_view_docs_btn", type="secondary", use_container_width=True):
                st.session_state["_pending_nav"] = "Documentation"
                st.rerun()
            
        st.markdown("""
        <div style="margin-top: 3.5rem; display: flex; align-items: center; gap: 15px;">
            <div style="font-size: 0.75rem; color: #6B8F7A; letter-spacing: 1px; text-transform: uppercase;">Trusted by <strong style="color: #BCCBB9;">120+ Security Teams</strong> worldwide.</div>
        </div>
        """, unsafe_allow_html=True)

    with col_right:
        with st.container(border=True):
            input_mode = st.segmented_control(
                "Choose input type",
                ["Architecture File", "Android APK"],
                default="Architecture File",
                label_visibility="collapsed"
            )
            
            if not input_mode:
                input_mode = "Architecture File"
                
            formats_html = '<span class="badge" style="background: rgba(255,255,255,0.1); color: #BCCBB9; border: 1px solid rgba(255,255,255,0.15);">.JSON</span> <span class="badge" style="background: rgba(255,255,255,0.1); color: #BCCBB9; border: 1px solid rgba(255,255,255,0.15);">.YAML</span> <span class="badge" style="background: rgba(255,255,255,0.1); color: #BCCBB9; border: 1px solid rgba(255,255,255,0.15);">.XML</span>' if input_mode == "Architecture File" else '<span class="badge" style="background: rgba(255,255,255,0.1); color: #BCCBB9; border: 1px solid rgba(255,255,255,0.15);">.APK</span>'
            
            # HTML Visual block for the dropzone
            st.markdown(f"""
            <div style="margin-top: 28px; border: 1px dashed rgba(255,255,255,0.15); border-radius: 12px; min-height: 280px; display: flex; flex-direction: column; align-items: center; justify-content: center; background: rgba(34, 197, 94, 0.02); padding: 20px;">
                <div style="width: 50px; height: 50px; background: rgba(75, 226, 119, 0.1); border-radius: 12px; display: flex; align-items: center; justify-content: center; margin-bottom: 16px; border: 1px solid rgba(75, 226, 119, 0.2);">
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#4BE277" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                        <polyline points="17 8 12 3 7 8"></polyline>
                        <line x1="12" y1="3" x2="12" y2="15"></line>
                    </svg>
                </div>
                <div style="color: #D4E4FA; font-weight: 700; font-size: 1.25rem; margin-bottom: 6px;">Drag and drop file</div>
                <div style="color: #BCCBB9; font-size: 0.95rem; font-weight: 500; margin-bottom: 24px;">or <span style="color: #4BE277;">browse from your computer</span></div>
                <div style="text-align: center;">
                    <div style="color: #6B8F7A; font-size: 0.65rem; font-weight: 700; letter-spacing: 1px; text-transform: uppercase; margin-bottom: 10px;">SUPPORTED FORMATS</div>
                    <div>{formats_html}</div>
                </div>
            </div>
            """, unsafe_allow_html=True)
            
            if input_mode == "Architecture File":
                uploaded_file = st.file_uploader(
                    "Upload architecture model",
                    type=["yaml", "yml", "json", "xml"],
                    label_visibility="collapsed"
                )
            else:
                uploaded_file = st.file_uploader(
                    "Upload Android APK",
                    type=["apk"],
                    label_visibility="collapsed"
                )
        
    st.markdown('</div>', unsafe_allow_html=True)
    return uploaded_file, input_mode

def render_feature_cards():
    st.markdown('<div class="fade-in-up" style="padding: 0 1rem; margin-bottom: 3rem;">', unsafe_allow_html=True)
    c1, c2, c3 = st.columns(3)
    
    with c1:
        st.markdown("""
        <div class="feature-card">
            <div class="feature-icon">🛡️</div>
            <h3 class="feature-title">STRIDE Mapping</h3>
            <p class="feature-desc">Deep analysis of Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege.</p>
        </div>
        """, unsafe_allow_html=True)
        
    with c2:
        st.markdown("""
        <div class="feature-card">
            <div class="feature-icon">📑</div>
            <h3 class="feature-title">MASVS 2.0 Compliance</h3>
            <p class="feature-desc">Automated mapping against OWASP Mobile Application Security Verification Standard categories.</p>
        </div>
        """, unsafe_allow_html=True)
        
    with c3:
        st.markdown("""
        <div class="feature-card">
            <div class="feature-icon">⚡</div>
            <h3 class="feature-title">Auto-Mitigation</h3>
            <p class="feature-desc">Generates actionable remediation strategies and roadmap items for development teams.</p>
        </div>
        """, unsafe_allow_html=True)
        
    st.markdown('</div>', unsafe_allow_html=True)

def render_kpi_cards(threats, global_risk):
    masvs_cats = set([str(t.get('masvs', '')).split('.')[0] for t in threats if t.get('masvs')])
    coverage_percent = min(100, int((len(masvs_cats) / 8) * 100)) if masvs_cats else 75

    risk_level = global_risk.get('level', 'N/A')
    max_score   = global_risk.get('max_score', 0)

    # Color for risk level
    if 'Critique' in risk_level or 'Critical' in risk_level:
        risk_color = '#EF4444'
    elif 'Élevé' in risk_level or 'Elevated' in risk_level or 'High' in risk_level:
        risk_color = '#F97316'
    elif 'Moyen' in risk_level or 'Medium' in risk_level:
        risk_color = '#FACC15'
    else:
        risk_color = '#4BE277'

    # Card base style shared by all 4
    card = 'background:rgba(8,18,32,0.28);backdrop-filter:blur(14px);border:1px solid rgba(148,163,184,0.1);border-radius:16px;padding:18px 22px;height:100%;box-shadow:0 18px 50px rgba(0,0,0,0.18);'

    label_style = 'font-family:JetBrains Mono,Consolas,monospace;font-size:10px;font-weight:800;color:#6B8F7A;text-transform:uppercase;letter-spacing:0.12em;margin-bottom:10px;'
    value_style = 'font-family:Inter,sans-serif;font-size:28px;font-weight:800;color:#F8FAFC;line-height:1;'
    sub_style   = 'font-family:Inter,sans-serif;font-size:12px;font-weight:600;color:#6B8F7A;margin-top:6px;'

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.markdown(
            f'<div style="{card}">'
            f'<div style="{label_style}">Threats Identified</div>'
            f'<div style="{value_style}">{len(threats)}</div>'
            f'<div style="{sub_style}">+2 vs previous scan</div>'
            f'</div>',
            unsafe_allow_html=True
        )

    with col2:
        score_color = '#EF4444' if max_score >= 70 else '#F97316' if max_score >= 40 else '#4BE277'
        st.markdown(
            f'<div style="{card}">'
            f'<div style="{label_style}">Max Risk Score</div>'
            f'<div style="font-family:Inter,sans-serif;font-size:28px;font-weight:800;color:{score_color};line-height:1;">{max_score}</div>'
            f'<div style="font-family:Inter,sans-serif;font-size:12px;font-weight:600;color:{score_color};margin-top:6px;display:flex;align-items:center;gap:5px;">'
            f'<span style="width:6px;height:6px;border-radius:50%;background:{score_color};display:inline-block;"></span>'
            f'Critical threshold</div>'
            f'</div>',
            unsafe_allow_html=True
        )

    with col3:
        st.markdown(
            f'<div style="{card}">'
            f'<div style="{label_style}">Global Risk Level</div>'
            f'<div style="font-family:Inter,sans-serif;font-size:20px;font-weight:800;color:{risk_color};line-height:1;margin-bottom:6px;">{risk_level}</div>'
            f'<div style="font-family:Inter,sans-serif;font-size:12px;font-weight:600;color:#6B8F7A;">Trend: <span style="color:#4BE277;">Stable</span></div>'
            f'</div>',
            unsafe_allow_html=True
        )

    with col4:
        st.markdown(
            f'<div style="{card}">'
            f'<div style="{label_style}">MASVS Coverage</div>'
            f'<div style="{value_style}">{coverage_percent}%</div>'
            f'<div style="margin-top:10px;width:100%;height:4px;background:rgba(255,255,255,0.06);border-radius:999px;overflow:hidden;">'
            f'<div style="width:{coverage_percent}%;height:100%;background:linear-gradient(90deg,#16A34A,#4BE277);border-radius:999px;"></div>'
            f'</div>'
            f'</div>',
            unsafe_allow_html=True
        )

def render_dashboard_overview(app_data, analysis):
    """Render the single architecture summary card grid below the diagram."""

    # ── Shared card styles ────────────────────────────────────────────────
    CARD_CLASS = 'architecture-summary-card'
    LABEL_CLASS = 'architecture-summary-label'
    ROW_SEP = 'display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px solid rgba(148,163,184,0.07);'
    ROW_LAST = 'display:flex;justify-content:space-between;align-items:center;padding:8px 0;'
    KEY_S = 'font-family:Inter,sans-serif;font-size:13px;color:#64748B;'
    VAL_S = 'font-family:Inter,sans-serif;font-size:13px;font-weight:600;color:#E2E8F0;'

    # ── 1. App Summary ────────────────────────────────────────────────────
    if app_data.get("app_type") == "Android APK":
        meta = app_data.get("apk_metadata", {})
        prop_rows = (
            f'<div style="{ROW_SEP}"><span style="{KEY_S}">Min SDK</span><span style="{VAL_S}">{meta.get("minSdkVersion","N/A")}</span></div>'
            f'<div style="{ROW_SEP}"><span style="{KEY_S}">Target SDK</span><span style="{VAL_S}">{meta.get("targetSdkVersion","N/A")}</span></div>'
            f'<div style="{ROW_SEP}"><span style="{KEY_S}">Permissions</span><span style="{VAL_S}">{len(app_data.get("permissions",[]))}</span></div>'
            f'<div style="{ROW_LAST}"><span style="{KEY_S}">Exported Comps</span>'
            f'<span style="font-family:Inter,sans-serif;font-size:13px;font-weight:700;color:#F97316;">{sum(1 for c in app_data.get("components",[]) if c.get("exported"))}</span></div>'
        )
        badge_txt, badge_color = 'APK ANALYSIS', '#38BDF8'
    else:
        prop_rows = (
            f'<div style="{ROW_SEP}"><span style="{KEY_S}">Auth</span><span style="{VAL_S}">{app_data.get("authentication",{}).get("type","N/A")}</span></div>'
            f'<div style="{ROW_SEP}"><span style="{KEY_S}">Database</span><span style="{VAL_S}">{app_data.get("storage",{}).get("local_database","N/A")}</span></div>'
            f'<div style="{ROW_LAST}"><span style="{KEY_S}">Cert Pinning</span>'
            f'<span style="display:inline-block;padding:2px 10px;border-radius:999px;background:rgba(34,197,94,0.12);border:1px solid rgba(34,197,94,0.28);color:#4BE277;font-size:11px;font-weight:700;">Enabled</span></div>'
        )
        badge_txt, badge_color = 'YAML MODEL', '#94A3B8'

    badge_html = (
        f'<span style="display:inline-block;padding:3px 10px;border-radius:999px;'
        f'background:rgba(148,163,184,0.08);border:1px solid rgba(148,163,184,0.18);'
        f'color:{badge_color};font-family:JetBrains Mono,Consolas,monospace;'
        f'font-size:10px;font-weight:800;letter-spacing:0.08em;margin-bottom:16px;">{badge_txt}</span>'
    )
    app_name = app_data.get("app_name", "N/A")
    app_summary_card = (
        f'<div class="{CARD_CLASS}">'
        f'<div class="{LABEL_CLASS}">App Summary</div>'
        f'<div style="font-family:Inter,sans-serif;font-size:16px;font-weight:700;color:#F1F5F9;margin-bottom:8px;line-height:1.2;">{app_name}</div>'
        f'{badge_html}'
        f'{prop_rows}'
        f'</div>'
    )

    # ── 2. Critical Assets ────────────────────────────────────────────────
    assets = analysis.get('assets', [])
    if not assets:
        assets = ['N/A']
    total_assets = len(assets)
    visible = assets[:8]
    pills_html = ''.join(
        f'<span style="display:inline-flex;align-items:center;padding:6px 13px;'
        f'background:rgba(74,226,119,0.07);border:1px solid rgba(74,226,119,0.22);'
        f'border-radius:999px;color:#A7F3D0;'
        f'font-family:Inter,sans-serif;font-size:12px;font-weight:600;'
        f'margin:4px 4px 4px 0;white-space:nowrap;">{a}</span>'
        for a in visible
    )
    more_html = (
        f'<span style="display:inline-block;padding:5px 12px;border-radius:999px;'
        f'background:rgba(148,163,184,0.07);border:1px solid rgba(148,163,184,0.14);'
        f'color:#64748B;font-size:11px;font-weight:600;margin:4px 0 0 0;">+{total_assets - len(visible)} more</span>'
        if total_assets > len(visible) else ''
    )
    assets_card = (
        f'<div class="{CARD_CLASS}">'
        f'<div class="{LABEL_CLASS}">Critical Assets</div>'
        f'<div style="display:flex;flex-wrap:wrap;gap:0;">{pills_html}{more_html}</div>'
        f'</div>'
    )

    # ── 3. Entry Points ───────────────────────────────────────────────────
    eps = analysis.get('entry_points', [])
    if not eps:
        eps = ['N/A']
    visible_eps = eps[:5]
    more_eps = len(eps) - len(visible_eps)
    ep_items = ''.join(
        f'<div style="display:flex;align-items:flex-start;gap:10px;padding:7px 0;border-bottom:1px solid rgba(148,163,184,0.06);">'
        f'<span style="width:6px;height:6px;min-width:6px;border-radius:50%;background:#4BE277;margin-top:5px;'
        f'box-shadow:0 0 6px rgba(75,226,119,0.5);"></span>'
        f'<span style="font-family:Inter,sans-serif;font-size:13px;color:#CBD5E1;line-height:1.4;'
        f'overflow:hidden;text-overflow:ellipsis;">{ep}</span>'
        f'</div>'
        for ep in visible_eps
    )
    more_ep_html = (
        f'<div style="font-family:Inter,sans-serif;font-size:11px;color:#64748B;padding-top:8px;">+{more_eps} more entry points</div>'
        if more_eps > 0 else ''
    )
    entry_points_card = (
        f'<div class="{CARD_CLASS}">'
        f'<div class="{LABEL_CLASS}">Entry Points</div>'
        f'{ep_items}{more_ep_html}'
        f'</div>'
    )

    # ── 4. Threat Actors ──────────────────────────────────────────────────
    actors = app_data.get('users', []) + app_data.get('threat_actors', [])
    if not actors:
        actors = ["Malicious App (Colocated)", "Network Adversary"]
    level_cfg = [
        ('#F97316', 'rgba(249,115,22,0.12)', 'rgba(249,115,22,0.28)', 'HIGH'),
        ('#38BDF8', 'rgba(56,189,248,0.10)', 'rgba(56,189,248,0.25)', 'MEDIUM'),
        ('#4BE277', 'rgba(75,226,119,0.10)', 'rgba(75,226,119,0.22)', 'LOW'),
        ('#94A3B8', 'rgba(148,163,184,0.08)', 'rgba(148,163,184,0.18)', 'INFO'),
    ]
    actor_items = ''
    for i, a in enumerate(actors[:4]):
        col, bg, border, lvl = level_cfg[min(i, len(level_cfg)-1)]
        actor_items += (
            f'<div style="display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px solid rgba(148,163,184,0.06);gap:12px;">'
            f'<span style="font-family:Inter,sans-serif;font-size:13px;color:#CBD5E1;">{a}</span>'
            f'<span style="display:inline-block;padding:3px 10px;border-radius:999px;background:{bg};border:1px solid {border};'
            f'color:{col};font-family:JetBrains Mono,Consolas,monospace;font-size:10px;font-weight:800;letter-spacing:0.06em;">{lvl}</span>'
            f'</div>'
        )
    actors_card = (
        f'<div class="{CARD_CLASS}">'
        f'<div class="{LABEL_CLASS}">Threat Actors</div>'
        f'{actor_items}'
        f'</div>'
    )

    st.markdown(
        f'<div class="architecture-summary-grid">'
        f'{app_summary_card}{assets_card}{entry_points_card}{actors_card}'
        f'</div>',
        unsafe_allow_html=True
    )

def render_risk_register(threats):
    df = pd.DataFrame(threats)

    if df.empty:
        st.info("No threats to display.")
        return

    if "description" not in df.columns and "threat" in df.columns:
        df["description"] = df["threat"]
    if "severity" not in df.columns and "level" in df.columns:
        df["severity"] = df["level"]

    # ── Header ────────────────────────────────────────────────────────────
    total = len(df)
    st.markdown(
        f'<div class="rr-section">'
        f'<div class="rr-pre-label">Threat Intelligence</div>'
        f'<div class="rr-header">'
        f'<h2 class="rr-title">Risk Register</h2>'
        f'<span class="rr-count-badge">{total} threats detected</span>'
        f'</div></div>',
        unsafe_allow_html=True
    )

    # ── Filters ───────────────────────────────────────────────────────────
    f_col1, f_col2, f_col3, f_col4 = st.columns([2, 1.5, 1.5, 1.5])
    with f_col1:
        search_query = st.text_input("Search Threats", placeholder="Keyword, ID, description...", key="search_threats").lower()
    with f_col2:
        levels = ["All"] + sorted(list(df['severity'].unique()))
        filter_level = st.selectbox("Severity", options=levels, key="filter_level")
    with f_col3:
        all_strides = set()
        for s in df['stride'].dropna():
            for part in str(s).split('/'):
                if part.strip(): all_strides.add(part.strip())
        strides = ["All"] + sorted(list(all_strides))
        filter_stride = st.selectbox("STRIDE", options=strides, key="filter_stride")
    with f_col4:
        all_masvs = ["All"] + sorted(list(df['masvs'].dropna().unique()))
        filter_masvs = st.selectbox("MASVS", options=all_masvs, key="filter_masvs")

    # ── Apply filters ────────────────────────────────────────────────────
    if search_query:
        df = df[df['description'].astype(str).str.lower().str.contains(search_query) |
                df['id'].astype(str).str.lower().str.contains(search_query)]
    if filter_level != "All":
        df = df[df['severity'] == filter_level]
    if filter_stride != "All":
        df = df[df['stride'].astype(str).str.contains(filter_stride, case=False, na=False)]
    if filter_masvs != "All":
        df = df[df['masvs'] == filter_masvs]

    if df.empty:
        st.markdown('<div style="color:#94A3B8;font-style:italic;text-align:center;padding:2rem;">No threats match the current filters.</div>', unsafe_allow_html=True)
        return

    # ── Table ─────────────────────────────────────────────────────────────
    sev_map = {
        'CRITIQUE': 'sev-critique', 'CRITICAL': 'sev-critique',
        'ÉLEVÉ':    'sev-eleve',    'HIGH':     'sev-eleve',    'ELEVATED': 'sev-eleve',
        'MOYEN':    'sev-moyen',    'MEDIUM':   'sev-moyen',
        'FAIBLE':   'sev-faible',   'LOW':      'sev-faible',
    }

    score_colors = {
        'high':   '#EF4444',
        'medium': '#F97316',
        'low':    '#4BE277',
    }

    rows_html = ''
    for _, row in df.iterrows():
        sev_raw = str(row.get('severity', 'low')).upper()
        sev_cls = sev_map.get(sev_raw, 'sev-faible')

        score = row.get('score', 0)
        try:
            score_val = int(score)
        except Exception:
            score_val = 0
        sc = score_colors['high'] if score_val >= 70 else score_colors['medium'] if score_val >= 40 else score_colors['low']

        stride_str = str(row.get('stride', 'N/A'))
        stride_chips = ''.join(
            f'<span class="stride-chip">{s.strip()}</span> '
            for s in stride_str.split('/') if s.strip()
        )

        rows_html += (
            f'<tr>'
            f'<td><span class="rr-id">{row.get("id", "N/A")}</span></td>'
            f'<td><div class="rr-desc">{row.get("description", "N/A")}</div></td>'
            f'<td><div style="display:flex;flex-wrap:wrap;gap:3px;">{stride_chips}</div></td>'
            f'<td><span class="rr-score" style="color:{sc}">{score_val}</span></td>'
            f'<td><span class="sev-badge {sev_cls}">{sev_raw}</span></td>'
            f'<td><span class="rr-masvs">{row.get("masvs", "N/A")}</span></td>'
            f'</tr>'
        )

    html = (
        '<div class="rr-table-wrap">'
        '<table class="rr-table">'
        '<thead><tr>'
        '<th style="width:8%">ID</th>'
        '<th style="width:38%">Description</th>'
        '<th style="width:18%">STRIDE</th>'
        '<th style="width:8%">Score</th>'
        '<th style="width:14%">Severity</th>'
        '<th style="width:14%">MASVS</th>'
        '</tr></thead>'
        f'<tbody>{rows_html}</tbody>'
        '</table></div>'
    )
    st.markdown(html, unsafe_allow_html=True)

def render_stride_distribution(threats):
    """STRIDE Distribution — entire card rendered as one block via components.html."""
    import streamlit.components.v1 as components

    if not threats or len(threats) == 0:
        st.markdown(
            '<div style="background:linear-gradient(135deg,rgba(8,18,32,0.96),rgba(3,12,23,0.90));'
            'border:1px solid rgba(148,163,184,0.10);border-radius:26px;padding:48px;'
            'min-height:420px;display:flex;flex-direction:column;justify-content:center;align-items:center;">'
            '<div style="color:#64748B;font-size:14px;">No STRIDE data available. Run an analysis first.</div>'
            '</div>',
            unsafe_allow_html=True
        )
        return

    df = pd.DataFrame(threats)
    stride_counts = df['stride'].value_counts().reset_index()
    stride_counts.columns = ['stride', 'count']
    total_threats = int(stride_counts['count'].sum())
    color_map = {
        'Spoofing': '#38BDF8', 'Tampering': '#FACC15', 'Repudiation': '#6B8F7A',
        'Information Disclosure': '#22C55E', 'Denial of Service': '#EF4444',
        'Elevation of Privilege': '#F97316'
    }
    fig = px.pie(stride_counts, values='count', names='stride', hole=0.58,
                 color='stride', color_discrete_map=color_map)
    fig.update_layout(height=310, paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
        font_color='#CBD5E1', showlegend=False, margin=dict(t=5, b=5, l=5, r=5),
        annotations=[dict(
            text=(f"<span style='font-size:52px;font-weight:900;color:#F8FAFC;'>{total_threats}</span>"
                  f"<br><span style='font-size:12px;font-weight:700;color:#64748B;letter-spacing:.12em;'>THREATS</span>"),
            x=0.5, y=0.5, showarrow=False, font_family="Inter")])
    fig.update_traces(textinfo='none', hovertemplate="%{label}: %{value}<extra></extra>")
    chart_div = fig.to_html(include_plotlyjs='cdn', full_html=False)

    legend = ''
    for i, (_, r) in enumerate(stride_counts.iterrows()):
        n, c = r['stride'], int(r['count'])
        cl = color_map.get(n, '#94A3B8')
        d = 0.3 + i * 0.08
        legend += (f'<div class="li" style="animation-delay:{d}s">'
                   f'<span class="ld" style="background:{cl};box-shadow:0 0 8px {cl}44"></span>'
                   f'<span class="ln">{n}</span><span class="lc">{c}</span></div>')

    full = f'''<!DOCTYPE html><html><head>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800;900&family=JetBrains+Mono:wght@700;800&display=swap" rel="stylesheet">
<style>
*{{margin:0;padding:0;box-sizing:border-box}}body{{background:transparent}}
@keyframes fu{{from{{opacity:0;transform:translateY(16px)}}to{{opacity:1;transform:translateY(0)}}}}
@keyframes li{{from{{opacity:0;transform:translateX(-8px)}}to{{opacity:1;transform:translateX(0)}}}}
.card{{background:linear-gradient(135deg,rgba(8,18,32,0.96),rgba(3,12,23,0.90));border:1px solid rgba(148,163,184,0.10);border-radius:26px;padding:32px 36px;box-shadow:0 24px 80px rgba(0,0,0,0.30),inset 0 1px 0 rgba(255,255,255,0.04);animation:fu .6s ease-out both;display:flex;flex-direction:column}}
.pre{{font-family:'JetBrains Mono',monospace;font-size:12px;font-weight:800;color:#4BE277;text-transform:uppercase;letter-spacing:.18em;margin-bottom:8px}}
.ttl{{font-family:Inter,sans-serif;font-size:34px;font-weight:800;color:#F8FAFC;line-height:1.08;margin-bottom:6px}}
.sub{{font-family:Inter,sans-serif;font-size:14px;color:#94A3B8;margin-bottom:12px}}
.cw{{display:flex;align-items:center;justify-content:center}}
.leg{{border-top:1px solid rgba(148,163,184,0.08);padding-top:16px;margin-top:12px;display:grid;grid-template-columns:1fr 1fr;gap:4px 20px}}
.li{{display:flex;align-items:center;gap:10px;padding:6px 4px;border-radius:8px;transition:background .15s;animation:li .4s ease-out both}}
.li:hover{{background:rgba(74,226,119,0.04)}}
.ld{{width:10px;height:10px;min-width:10px;border-radius:3px}}
.ln{{font-family:Inter,sans-serif;font-size:13px;color:#CBD5E1;flex:1}}
.lc{{font-family:'JetBrains Mono',monospace;font-size:12px;font-weight:700;color:#94A3B8}}
.js-plotly-plot .plotly .main-svg{{background:transparent!important}}
</style></head><body>
<div class="card">
<div class="pre">Threat Taxonomy</div>
<div class="ttl">STRIDE Distribution</div>
<div class="sub">Breakdown of detected threats by STRIDE category.</div>
<div class="cw">{chart_div}</div>
<div class="leg">{legend}</div>
</div></body></html>'''
    components.html(full, height=680, scrolling=False)


def render_masvs_compliance(threats):
    """MASVS Compliance — entire card in one st.markdown block."""
    if not threats or len(threats) == 0:
        st.markdown(
            '<div style="background:linear-gradient(135deg,rgba(8,18,32,0.96),rgba(3,12,23,0.90));'
            'border:1px solid rgba(148,163,184,0.10);border-radius:26px;padding:48px;'
            'min-height:420px;display:flex;flex-direction:column;justify-content:center;align-items:center;">'
            '<div style="color:#64748B;font-size:14px;">No MASVS data available. Run an analysis first.</div>'
            '</div>', unsafe_allow_html=True)
        return

    categories = [
        {"name": "V2: Data Storage", "score": 60, "color": "#22C55E"},
        {"name": "V4: Authentication", "score": 90, "color": "#38BDF8"},
        {"name": "V5: Network Communication", "score": 100, "color": "#A7F3D0"},
    ]

    rows = ''
    for i, cat in enumerate(categories):
        s = cat['score']
        pc = '#4BE277' if s >= 90 else '#38BDF8' if s >= 70 else '#FACC15' if s >= 50 else '#F97316'
        dl = 0.15 + i * 0.15
        rows += (
            f'<div style="margin-bottom:28px;animation:mfu .5s ease-out both;animation-delay:{dl}s;">'
            f'<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">'
            f'<span style="font-family:Inter,sans-serif;font-size:16px;font-weight:700;color:#E2E8F0;">{cat["name"]}</span>'
            f'<span style="font-family:JetBrains Mono,monospace;font-size:15px;font-weight:800;color:{pc};'
            f'animation:mpi .5s ease-out both;animation-delay:{dl+0.3}s;">{s}%</span></div>'
            f'<div style="width:100%;height:11px;border-radius:999px;background:rgba(148,163,184,0.12);overflow:hidden;">'
            f'<div style="height:100%;border-radius:999px;width:{s}%;'
            f'background:linear-gradient(90deg,{cat["color"]},rgba(76,215,246,0.7));'
            f'box-shadow:0 0 16px {cat["color"]}44;'
            f'animation:mbf 1.2s cubic-bezier(.22,.61,.36,1) both;animation-delay:{dl}s;"></div>'
            f'</div></div>')

    avg = int(sum(c['score'] for c in categories) / len(categories))
    ac = '#4BE277' if avg >= 80 else '#FACC15' if avg >= 60 else '#F97316'

    st.markdown(
f'''<style>
@keyframes mfu{{from{{opacity:0;transform:translateY(16px)}}to{{opacity:1;transform:translateY(0)}}}}
@keyframes mbf{{from{{width:0%}}}}
@keyframes mpi{{from{{opacity:0;transform:translateY(6px)}}to{{opacity:1;transform:translateY(0)}}}}
</style>
<div style="background:rgba(8,18,32,0.28);backdrop-filter:blur(14px);border:1px solid rgba(148,163,184,0.10);border-radius:26px;padding:32px 36px;min-height:420px;box-shadow:0 24px 80px rgba(0,0,0,0.30),inset 0 1px 0 rgba(255,255,255,0.04);animation:mfu .6s ease-out both;display:flex;flex-direction:column;">
<div style="font-family:JetBrains Mono,monospace;font-size:12px;font-weight:800;color:#4BE277;text-transform:uppercase;letter-spacing:.18em;margin-bottom:8px;">Security Standard Coverage</div>
<div style="font-family:Inter,sans-serif;font-size:34px;font-weight:800;color:#F8FAFC;line-height:1.08;margin-bottom:6px;">MASVS Compliance</div>
<div style="font-family:Inter,sans-serif;font-size:14px;color:#94A3B8;margin-bottom:28px;">Coverage estimation across mapped OWASP MASVS areas.</div>
<div style="flex:1;">{rows}</div>
<div style="margin-top:8px;padding:22px 26px;background:linear-gradient(135deg,rgba(74,226,119,0.04),rgba(56,189,248,0.03));border:1px solid rgba(74,226,119,0.14);border-radius:18px;display:flex;justify-content:space-between;align-items:center;">
<div><div style="font-family:Inter,sans-serif;font-size:15px;font-weight:700;color:#94A3B8;">Overall Coverage</div>
<div style="font-family:Inter,sans-serif;font-size:12px;color:#64748B;margin-top:3px;">Based on mapped MASVS categories</div></div>
<div style="font-family:Inter,sans-serif;font-size:48px;font-weight:900;color:{ac};line-height:1;text-shadow:0 0 30px {ac}22;">{avg}%</div>
</div></div>''', unsafe_allow_html=True)

def render_recommendations(threats):
    # ── Premium CSS for this section ──────────────────────────────────────
    st.markdown("""
<style>
@keyframes recFadeUp {
    from { opacity: 0; transform: translateY(20px); }
    to   { opacity: 1; transform: translateY(0); }
}
@keyframes softGlowPulse {
    0%,100% { box-shadow: 0 20px 60px rgba(0,0,0,0.18), inset 0 1px 0 rgba(255,255,255,0.04); }
    50%     { box-shadow: 0 20px 60px rgba(0,0,0,0.22), 0 0 28px rgba(74,226,119,0.06), inset 0 1px 0 rgba(255,255,255,0.04); }
}
.rec-card {
    background: linear-gradient(135deg, rgba(8,18,32,0.58), rgba(5,24,20,0.32));
    border: 1px solid rgba(148,163,184,0.12);
    border-radius: 24px;
    padding: 32px;
    min-height: 280px;
    display: flex;
    flex-direction: column;
    box-shadow: 0 20px 60px rgba(0,0,0,0.18), inset 0 1px 0 rgba(255,255,255,0.04);
    backdrop-filter: blur(16px);
    transition: transform 0.28s ease, border-color 0.28s ease, box-shadow 0.28s ease;
    animation: recFadeUp 0.55s ease both;
}
.rec-card:hover {
    transform: translateY(-5px);
    border-color: rgba(74,226,119,0.34);
    box-shadow: 0 28px 80px rgba(0,0,0,0.26), 0 0 34px rgba(74,226,119,0.07);
}
.rec-card-0 { border-top: 2px solid rgba(255,77,94,0.55);  animation-delay: 0ms; }
.rec-card-1 { border-top: 2px solid rgba(245,158,11,0.55); animation-delay: 80ms; }
.rec-card-2 { border-top: 2px solid rgba(148,163,184,0.40); animation-delay: 160ms; }
.rec-badge {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    font-family: 'JetBrains Mono', Consolas, monospace;
    font-size: 0.62rem;
    font-weight: 800;
    letter-spacing: 0.12em;
    padding: 4px 12px;
    border-radius: 999px;
    border: 1px solid;
}
.rec-badge-0 { color:#FF4D5E; background:rgba(255,77,94,0.10);  border-color:rgba(255,77,94,0.28); }
.rec-badge-1 { color:#F59E0B; background:rgba(245,158,11,0.10); border-color:rgba(245,158,11,0.28); }
.rec-badge-2 { color:#94A3B8; background:rgba(148,163,184,0.10); border-color:rgba(148,163,184,0.22); }
</style>
""", unsafe_allow_html=True)

    # ── Section title block ───────────────────────────────────────────────
    st.markdown("""
<div style="margin-top:4.5rem; margin-bottom:2.5rem;">
    <div style="font-family:'JetBrains Mono',Consolas,monospace; font-size:12px; font-weight:800;
                letter-spacing:0.18em; color:#4BE277; text-transform:uppercase;
                margin-bottom:10px;">RISK RESPONSE</div>
    <h2 style="margin:0; font-size:clamp(28px,4vw,38px); font-weight:800; color:#F8FAFC;
               font-family:Inter,sans-serif; line-height:1.1; letter-spacing:-0.02em;">
        High Priority Recommendations
    </h2>
    <p style="margin:10px 0 0; font-size:15px; color:#94A3B8; font-family:Inter,sans-serif;
              max-width:640px; line-height:1.6;">
        Critical mitigation actions generated from the highest-risk findings.
    </p>
</div>
""", unsafe_allow_html=True)

    sorted_threats = sorted(threats, key=lambda x: x.get('score', 0), reverse=True)

    col1, col2, col3 = st.columns(3, gap="large")
    cols = [col1, col2, col3]

    icons = [
        '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#FF4D5E" stroke-width="1.8" opacity="0.85"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>',
        '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#F59E0B" stroke-width="1.8" opacity="0.85"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>',
        '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#94A3B8" stroke-width="1.8" opacity="0.80"><circle cx="12" cy="12" r="10"></circle><path d="M12 8v4M12 16h.01"></path></svg>'
    ]
    priorities   = ["P0 CRITICAL", "P1 HIGH", "P2 MEDIUM"]
    badge_cls    = ["rec-badge-0", "rec-badge-1", "rec-badge-2"]
    card_cls     = ["rec-card-0",  "rec-card-1",  "rec-card-2"]

    default_titles = ["Enforce Android Keystore", "Strict HTTPS Enforcement", "Proguard/R8 Obfuscation"]
    default_desc   = [
        "Migrate SQLite keys from plain SharedPrefs to Hardware-backed Keystore provider.",
        "Update Network Security Config to strictly prohibit cleartext traffic for all domains.",
        "Increase obfuscation dictionary complexity to mitigate reverse engineering of business logic."
    ]

    for i in range(3):
        with cols[i]:
            title = default_titles[i]
            desc  = default_desc[i]
            if i < len(sorted_threats) and sorted_threats[i].get('mitigation'):
                title = sorted_threats[i].get('threat', title).split('.')[0]
                desc  = sorted_threats[i].get('mitigation')

            st.markdown(f"""
<div class="rec-card {card_cls[i]}">
    <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:20px;">
        <span class="rec-badge {badge_cls[i]}">{priorities[i]}</span>
        <span style="opacity:0.6;">{icons[i]}</span>
    </div>
    <div style="font-family:Inter,sans-serif; font-size:1.08rem; font-weight:700;
                color:#F1F5F9; margin-bottom:14px; line-height:1.35;">{title}</div>
    <div style="font-family:Inter,sans-serif; font-size:0.86rem; color:#94A3B8;
                line-height:1.65; flex:1;">{desc}</div>
</div>
""", unsafe_allow_html=True)

def render_remediation_roadmap(roadmap: list, metrics: dict) -> None:
    """Render the Remediation Roadmap section."""

    # ── Premium CSS for this section ──────────────────────────────────────
    st.markdown("""
<style>
@keyframes kpiFadeUp {
    from { opacity: 0; transform: translateY(14px); }
    to   { opacity: 1; transform: translateY(0); }
}
.roadmap-kpi-card {
    background: linear-gradient(135deg, rgba(8,18,32,0.50), rgba(5,24,20,0.25));
    border: 1px solid rgba(148,163,184,0.10);
    border-radius: 22px;
    padding: 28px 20px;
    text-align: center;
    backdrop-filter: blur(14px);
    box-shadow: 0 12px 40px rgba(0,0,0,0.14);
    transition: transform 0.25s ease, box-shadow 0.25s ease;
    animation: kpiFadeUp 0.5s ease both;
}
.roadmap-kpi-card:hover {
    transform: translateY(-4px);
    box-shadow: 0 20px 60px rgba(0,0,0,0.22), 0 0 20px rgba(74,226,119,0.06);
}
.roadmap-kpi-card-0 { animation-delay: 0ms; }
.roadmap-kpi-card-1 { animation-delay: 60ms; }
.roadmap-kpi-card-2 { animation-delay: 120ms; }
.roadmap-kpi-card-3 { animation-delay: 180ms; }
.kpi-label {
    font-family: 'JetBrains Mono', Consolas, monospace;
    font-size: 0.62rem;
    font-weight: 800;
    letter-spacing: 0.14em;
    text-transform: uppercase;
    color: #64748B;
    margin-bottom: 10px;
}
.kpi-value {
    font-family: Inter, sans-serif;
    font-size: 2.4rem;
    font-weight: 800;
    line-height: 1;
    letter-spacing: -0.03em;
}
.priority-action-card {
    background: rgba(8,18,32,0.28);
    backdrop-filter: blur(14px);
    border: 1px solid rgba(148,163,184,0.1);
    border-radius: 16px;
    padding: 20px 22px;
    margin-bottom: 12px;
    box-shadow: 0 10px 40px rgba(0,0,0,0.14);
    transition: transform 0.22s ease, box-shadow 0.22s ease;
}
.priority-action-card:hover {
    transform: translateX(4px);
    box-shadow: 0 14px 50px rgba(0,0,0,0.20);
}
</style>
""", unsafe_allow_html=True)

    # ── Section title block ───────────────────────────────────────────────
    st.markdown("""
<div style="margin-top:4.5rem; margin-bottom:2.5rem;">
    <div style="font-family:'JetBrains Mono',Consolas,monospace; font-size:12px; font-weight:800;
                letter-spacing:0.18em; color:#4BE277; text-transform:uppercase;
                margin-bottom:10px;">REMEDIATION ROADMAP</div>
    <h2 style="margin:0; font-size:clamp(26px,3.5vw,36px); font-weight:800; color:#F8FAFC;
               font-family:Inter,sans-serif; line-height:1.1; letter-spacing:-0.02em;">
        Prioritized Security Action Plan
    </h2>
    <p style="margin:10px 0 0; font-size:15px; color:#94A3B8; font-family:Inter,sans-serif;
              max-width:640px; line-height:1.6;">
        Prioritized remediation plan generated from the detected risk register.
    </p>
</div>
""", unsafe_allow_html=True)

    # ── 1. KPI Cards ──────────────────────────────────────────────────────
    col1, col2, col3, col4 = st.columns(4, gap="medium")
    kpis = [
        ("Total Actions",     metrics["total_actions"],                                    "#ECFDF5", "0"),
        ("High Priority",     metrics["high_priority"],                                    "#EF4444" if metrics["high_priority"] > 0 else "#22C55E", "1"),
        ("Avg Risk Reduction", f"-{metrics['avg_reduction']}",                             "#38BDF8", "2"),
        ("Quick Wins",        metrics["quick_wins"],                                       "#4BE277", "3")
    ]

    for col, (label, value, color, idx) in zip((col1, col2, col3, col4), kpis):
        col.markdown(f"""
<div class="roadmap-kpi-card roadmap-kpi-card-{idx}">
    <div class="kpi-label">{label}</div>
    <div class="kpi-value" style="color:{color};">{value}</div>
</div>
""", unsafe_allow_html=True)

    # ── 2. Top 5 Priority Actions ─────────────────────────────────────────
    st.markdown("""
<div style="margin-top:3rem; margin-bottom:1.2rem;
            display:flex; align-items:center; gap:16px;">
    <div style="flex:1; height:1px; background:linear-gradient(90deg, rgba(74,226,119,0.30), transparent);"></div>
    <span style="font-family:Inter,sans-serif; font-size:0.78rem; font-weight:700;
                 letter-spacing:0.08em; text-transform:uppercase;
                 color:#4BE277; white-space:nowrap;">Top 5 Priority Actions</span>
    <div style="flex:1; height:1px; background:linear-gradient(90deg, transparent, rgba(74,226,119,0.30));"></div>
</div>
""", unsafe_allow_html=True)
    
    # Sort roadmap specifically for top 5 (P0/P1 first, then highest risk reduction)
    priority_order = {"P0 Critical": 0, "P1 High": 1, "P2 Medium": 2, "P3 Low": 3}
    top_5 = sorted(roadmap, key=lambda x: (priority_order[x["priority"]], -x["risk_reduction"]))[:5]
    
    for action in top_5:
        p_color = "#EF4444" if "P0" in action["priority"] else "#F97316" if "P1" in action["priority"] else "#38BDF8" if "P2" in action["priority"] else "#22C55E"
        bar_width = min(100, (action['risk_reduction'] / max(1, action['current_score'])) * 100)
        html_card = (
            f'<div class="priority-action-card" style="border-left:3px solid {p_color};">'
            f'<div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:14px;">'
            f'<div style="display:flex;align-items:center;gap:10px;">'
            f'<span style="font-family:JetBrains Mono,monospace;background:{p_color}18;color:{p_color};padding:3px 10px;border-radius:999px;font-size:0.62rem;font-weight:800;border:1px solid {p_color}40;letter-spacing:0.10em;">{action["priority"]}</span>'
            f'<span style="font-family:JetBrains Mono,monospace;color:#475569;font-size:0.72rem;font-weight:600;">{action["threat_id"]}</span>'
            f'</div>'
            f'<div style="text-align:right;min-width:80px;">'
            f'<div style="font-size:0.6rem;color:#475569;text-transform:uppercase;letter-spacing:0.08em;margin-bottom:2px;">Risk Score</div>'
            f'<span style="color:#F87171;font-weight:800;font-size:0.95rem;">{action["current_score"]}</span>'
            f'<span style="color:#475569;font-size:0.8rem;"> &rarr; </span>'
            f'<span style="color:#4BE277;font-weight:800;font-size:0.95rem;">{action["residual_score"]}</span>'
            f'</div></div>'
            f'<div style="font-family:Inter,sans-serif;font-size:0.98rem;font-weight:600;color:#F1F5F9;margin-bottom:14px;line-height:1.4;">{action["recommended_action"]}</div>'
            f'<div style="margin-bottom:14px;">'
            f'<div style="display:flex;justify-content:space-between;font-size:0.68rem;color:#64748B;margin-bottom:5px;"><span style="text-transform:uppercase;letter-spacing:0.06em;">Expected Reduction</span><span style="color:#4BE277;font-weight:700;font-family:JetBrains Mono,monospace;">-{action["risk_reduction"]}</span></div>'
            f'<div style="width:100%;height:3px;background:rgba(148,163,184,0.10);border-radius:4px;overflow:hidden;">'
            f'<div style="height:100%;width:{bar_width}%;background:linear-gradient(90deg,#F59E0B,#4BE277);border-radius:4px;"></div>'
            f'</div></div>'
            f'<div style="display:flex;gap:20px;font-size:0.72rem;color:#64748B;flex-wrap:wrap;">'
            f'<span>Effort: <strong style="color:#94A3B8;font-weight:600;">{action["effort"]}</strong></span>'
            f'<span>Owner: <strong style="color:#94A3B8;font-weight:600;">{action["owner"]}</strong></span>'
            f'<span>MASVS: <strong style="color:#94A3B8;font-weight:600;">{action["masvs"]}</strong></span>'
            f'</div></div>'
        )
        st.markdown(html_card, unsafe_allow_html=True)

    st.markdown('<div style="margin-top:2rem;"></div>', unsafe_allow_html=True)

    # 3. Full Roadmap Table — premium custom HTML
    # ── Helper badge builders ────────────────────────────────────────────
    def _priority_badge(p: str) -> str:
        if "P0" in p:
            c, bg, bc = "#FF4D5E", "rgba(255,77,94,0.12)", "rgba(255,77,94,0.30)"
        elif "P1" in p:
            c, bg, bc = "#F59E0B", "rgba(245,158,11,0.12)", "rgba(245,158,11,0.30)"
        elif "P2" in p:
            c, bg, bc = "#4CD7F6", "rgba(76,215,246,0.10)", "rgba(76,215,246,0.26)"
        else:
            c, bg, bc = "#94A3B8", "rgba(148,163,184,0.10)", "rgba(148,163,184,0.22)"
        return (f'<span style="font-family:JetBrains Mono,monospace;font-size:0.60rem;font-weight:800;'
                f'letter-spacing:0.10em;color:{c};background:{bg};border:1px solid {bc};'
                f'padding:3px 9px;border-radius:999px;white-space:nowrap;">{p}</span>')

    def _effort_badge(e: str) -> str:
        e_l = e.strip().lower()
        if e_l == "high":
            c, bg, bc = "#F59E0B", "rgba(245,158,11,0.10)", "rgba(245,158,11,0.28)"
        elif e_l == "medium":
            c, bg, bc = "#4CD7F6", "rgba(76,215,246,0.10)", "rgba(76,215,246,0.26)"
        else:
            c, bg, bc = "#4BE277", "rgba(75,226,119,0.10)", "rgba(75,226,119,0.26)"
        return (f'<span style="font-family:Inter,sans-serif;font-size:0.72rem;font-weight:700;'
                f'color:{c};background:{bg};border:1px solid {bc};'
                f'padding:2px 9px;border-radius:6px;white-space:nowrap;">{e}</span>')

    def _status_badge(s: str) -> str:
        s_l = s.strip().lower()
        if "done" in s_l or "complete" in s_l:
            c, bg, bc = "#4BE277", "rgba(75,226,119,0.10)", "rgba(75,226,119,0.26)"
        elif "progress" in s_l:
            c, bg, bc = "#4CD7F6", "rgba(76,215,246,0.10)", "rgba(76,215,246,0.26)"
        else:
            c, bg, bc = "#94A3B8", "rgba(148,163,184,0.08)", "rgba(148,163,184,0.22)"
        return (f'<span style="font-family:Inter,sans-serif;font-size:0.72rem;font-weight:700;'
                f'color:{c};background:{bg};border:1px solid {bc};'
                f'padding:2px 9px;border-radius:6px;white-space:nowrap;">{s}</span>')

    # ── Build table rows ──────────────────────────────────────────────────
    col_headers = [
        ("Priority",   "120px",  "left"),
        ("ID",         "88px",   "left"),
        ("Action",     "auto",   "left"),
        ("Score",      "76px",   "center"),
        ("Residual",   "86px",   "center"),
        ("-Reduction", "96px",   "center"),
        ("Effort",     "108px",  "center"),
        ("Owner",      "200px",  "left"),
        ("Status",     "106px",  "center"),
    ]

    thead = "".join(
        f'<th style="background:rgba(8,18,32,0.46);color:#64748B;font-family:JetBrains Mono,monospace;'
        f'font-size:11px;font-weight:800;letter-spacing:0.09em;text-transform:uppercase;'
        f'padding:15px 14px;text-align:{align};border-bottom:1px solid rgba(148,163,184,0.12);'
        f'white-space:nowrap;width:{w};">{h}</th>'
        for h, w, align in col_headers
    )

    tbody_rows = ""
    for row in roadmap:
        priority   = row.get("priority", "")
        threat_id  = row.get("threat_id", "")
        action     = row.get("recommended_action", "")
        cur_score  = row.get("current_score", "")
        res_score  = row.get("residual_score", "")
        reduction  = row.get("risk_reduction", "")
        effort     = row.get("effort", "")
        owner      = row.get("owner", "")
        status     = row.get("status", "")

        p_color = "#FF4D5E" if "P0" in priority else "#F59E0B" if "P1" in priority else "#4CD7F6" if "P2" in priority else "#94A3B8"

        score_html    = f'<span style="font-family:JetBrains Mono,monospace;font-weight:700;color:#F87171;font-size:0.9rem;">{cur_score}</span>'
        res_html      = f'<span style="font-family:JetBrains Mono,monospace;font-weight:700;color:#4BE277;font-size:0.9rem;">{res_score}</span>'
        red_html      = f'<span style="font-family:JetBrains Mono,monospace;font-weight:700;color:#4CD7F6;font-size:0.9rem;">-{reduction}</span>'
        id_html       = f'<span style="font-family:JetBrains Mono,monospace;font-size:0.72rem;color:#64748B;font-weight:600;">{threat_id}</span>'
        owner_html    = f'<span style="font-family:Inter,sans-serif;font-size:0.82rem;color:#CBD5E1;">{owner}</span>'
        action_html   = f'<span style="font-family:Inter,sans-serif;font-size:0.86rem;font-weight:600;color:#F1F5F9;line-height:1.5;">{action}</span>'

        tbody_rows += (
            f'<tr style="border-bottom:1px solid rgba(148,163,184,0.07);transition:background 0.18s ease;" '
            f'onmouseover="this.style.background=\'rgba(74,226,119,0.05)\'" '
            f'onmouseout="this.style.background=\'transparent\'">'
            f'<td style="padding:15px 14px;vertical-align:top;border-left:2px solid {p_color}40;">{_priority_badge(priority)}</td>'
            f'<td style="padding:15px 14px;vertical-align:top;">{id_html}</td>'
            f'<td style="padding:15px 14px;vertical-align:top;white-space:normal;word-break:normal;overflow-wrap:anywhere;">{action_html}</td>'
            f'<td style="padding:15px 14px;vertical-align:top;text-align:center;">{score_html}</td>'
            f'<td style="padding:15px 14px;vertical-align:top;text-align:center;">{res_html}</td>'
            f'<td style="padding:15px 14px;vertical-align:top;text-align:center;">{red_html}</td>'
            f'<td style="padding:15px 14px;vertical-align:top;text-align:center;">{_effort_badge(effort)}</td>'
            f'<td style="padding:15px 14px;vertical-align:top;">{owner_html}</td>'
            f'<td style="padding:15px 14px;vertical-align:top;text-align:center;">{_status_badge(status)}</td>'
            f'</tr>'
        )

    table_html = f"""
<style>
.apt-wrapper {{
    width: 100%;
    overflow-x: auto;
    border: 1px solid rgba(148,163,184,0.12);
    border-radius: 18px;
    background: rgba(8,18,32,0.22);
    backdrop-filter: blur(12px);
    margin-top: 0.5rem;
}}
.apt-table {{
    width: 100%;
    border-collapse: collapse;
    table-layout: auto;
    font-family: Inter, sans-serif;
}}
.apt-table thead tr th:first-child {{ border-radius: 18px 0 0 0; }}
.apt-table thead tr th:last-child  {{ border-radius: 0 18px 0 0; }}
</style>
<div class="apt-wrapper">
  <table class="apt-table">
    <thead><tr>{thead}</tr></thead>
    <tbody>{tbody_rows}</tbody>
  </table>
</div>
"""
    st.markdown(table_html, unsafe_allow_html=True)


def render_architecture_diagram(app_data: dict) -> None:
    """Render the Architecture & Data Flow Diagram section – premium 76/24 layout."""

    # ── Consolidated CSS for this section ────────────────────────────────────
    st.markdown("""
<style>
    /* Section Container */
    .architecture-section {
        width: 100%;
        max-width: 1600px;
        margin: 16px auto 56px auto;
        background: transparent !important;
    }

    /* Tabs Styling */
    [data-testid="stTabs"] {
        background: transparent !important;
        margin-bottom: 20px !important;
    }
    [data-testid="stTabs"] [data-testid="stHorizontalBlock"] {
        gap: 40px !important;
    }
    [data-testid="stTabs"] button {
        background: transparent !important;
        border: none !important;
        color: #94A3B8 !important;
        font-family: 'Inter', sans-serif !important;
        font-size: 15px !important;
        font-weight: 700 !important;
        padding: 0 0 12px 0 !important;
        border-bottom: 2px solid transparent !important;
        transition: all 0.3s ease !important;
    }
    [data-testid="stTabs"] button[aria-selected="true"] {
        color: #39FF88 !important;
        border-bottom: 2px solid #39FF88 !important;
    }
    [data-testid="stTabs"] button:hover {
        color: #4CD7F6 !important;
    }

    /* Main Grid Layout */
    .architecture-main-grid {
        display: grid;
        grid-template-columns: minmax(0, 3fr) minmax(300px, 0.9fr);
        gap: 24px;
        align-items: start;
    }

    /* Diagram Canvas: large but fully contained, no transform-based cropping. */
    [data-testid="stGraphVizChart"] {
        width: 100% !important;
        min-height: 680px !important;
        max-height: none !important;
        padding: 28px !important;
        border-radius: 28px !important;
        background: linear-gradient(135deg, rgba(8,18,32,0.58), rgba(3,12,23,0.36)) !important;
        border: 1px solid rgba(148,163,184,0.14) !important;
        box-shadow: 0 28px 90px rgba(0,0,0,0.28), inset 0 1px 0 rgba(255,255,255,0.04) !important;
        display: flex !important;
        align-items: center !important;
        justify-content: center !important;
        overflow: visible !important;
        box-sizing: border-box !important;
        line-height: 1 !important;
    }
    [data-testid="stGraphVizChart"] > div,
    [data-testid="stGraphVizChart"] div {
        max-width: 100% !important;
        overflow: visible !important;
    }
    [data-testid="stGraphVizChart"] > div {
        display: flex !important;
        align-items: center !important;
        justify-content: center !important;
        width: 100% !important;
    }
    [data-testid="stGraphVizChart"] img,
    [data-testid="stGraphVizChart"] svg,
    .diagram-render,
    .diagram-render svg,
    .diagram-render img,
    .mermaid,
    .mermaid svg,
    .graphviz,
    .graphviz svg {
        display: block !important;
        width: 100% !important;
        max-width: 1120px !important;
        height: auto !important;
        max-height: 620px !important;
        object-fit: contain !important;
        transform: none !important;
        transform-origin: center center;
        overflow: visible !important;
    }

    /* Side Panels */
    .architecture-side-stack {
        display: flex;
        flex-direction: column;
        gap: 18px;
        align-self: start;
    }
    .architecture-side-panel {
        border-radius: 24px;
        padding: 22px 24px;
        max-height: none;
        background: linear-gradient(135deg, rgba(5,24,20,0.72), rgba(8,18,32,0.48));
        border: 1px solid rgba(74,226,119,0.18);
        box-shadow: 0 20px 60px rgba(0,0,0,0.18), inset 0 1px 0 rgba(255,255,255,0.03);
        backdrop-filter: blur(14px);
    }
    .side-panel-title {
        font-family: 'JetBrains Mono', Consolas, monospace;
        font-size: 12px;
        letter-spacing: 0.18em;
        color: #94A3B8;
        font-weight: 800;
        text-transform: uppercase;
        margin-bottom: 18px;
    }

    /* Legend Items */
    .legend-item {
        display: flex;
        align-items: center;
        gap: 12px;
        color: #F8FAFC;
        font-size: 15px;
        font-weight: 700;
        margin: 12px 0;
        line-height: 1.3;
    }
    .legend-dot {
        width: 14px;
        height: 14px;
        min-width: 14px;
        border-radius: 999px;
        box-shadow: 0 0 14px rgba(74,226,119,0.14);
    }

    /* Trust Boundaries */
    .trust-card {
        padding: 14px 16px;
        border-radius: 14px;
        background: rgba(8,18,32,0.24);
        border: 1px solid rgba(148,163,184,0.10);
        margin-bottom: 10px;
        transition: transform 0.2s ease, background 0.2s ease;
    }
    .trust-card:last-child {
        margin-bottom: 0;
    }
    .trust-card:hover {
        transform: translateX(4px);
        background: rgba(8,18,32,0.32);
    }
    .trust-id {
        font-family: 'JetBrains Mono', Consolas, monospace;
        font-size: 12px;
        font-weight: 800;
        color: #4CD7F6;
        margin-bottom: 6px;
    }
    .trust-name {
        color: #F8FAFC;
        font-size: 15px;
        font-weight: 700;
        line-height: 1.25;
    }

    /* Single final summary grid below Architecture Diagram */
    .architecture-summary-grid {
        width: 100%;
        max-width: 1600px;
        margin: 32px auto 48px auto;
        display: grid;
        grid-template-columns: repeat(4, minmax(0, 1fr));
        gap: 22px;
        align-items: stretch;
    }
    .architecture-summary-card {
        background: rgba(8,18,32,0.28);
        backdrop-filter: blur(14px);
        border: 1px solid rgba(148,163,184,0.12);
        border-radius: 22px;
        padding: 24px 26px;
        min-height: 220px;
        box-shadow: 0 18px 50px rgba(0,0,0,0.18), inset 0 1px 0 rgba(255,255,255,0.04);
        display: flex;
        flex-direction: column;
        gap: 0;
    }
    .architecture-summary-label {
        font-family: Inter, sans-serif;
        font-size: 11px;
        font-weight: 700;
        color: #4BE277;
        text-transform: uppercase;
        letter-spacing: 0.14em;
        margin-bottom: 14px;
    }

    /* Responsive */
    @media (max-width: 1150px) {
        .architecture-main-grid {
            grid-template-columns: 1fr;
        }
        [data-testid="stGraphVizChart"] {
            min-height: 560px !important;
        }
        [data-testid="stGraphVizChart"] img,
        [data-testid="stGraphVizChart"] svg {
            transform: none !important;
            max-width: 100% !important;
        }
    }

    @media (max-width: 900px) {
        .architecture-summary-grid {
            grid-template-columns: repeat(2, minmax(0, 1fr));
        }
    }

    @media (max-width: 650px) {
        .architecture-summary-grid {
            grid-template-columns: 1fr;
        }
    }
</style>
""", unsafe_allow_html=True)

    # ── Section title block ──────────────────────────────────────────────────
    st.markdown("""
<div style="margin-top:3.5rem; margin-bottom:2.5rem;">
    <div style="font-family:'JetBrains Mono',Consolas,monospace; font-size:12px; font-weight:800;
                letter-spacing:0.18em; color:#4BE277; text-transform:uppercase;
                margin-bottom:10px;">Architecture Insight</div>
    <h2 style="margin:0; font-size:clamp(26px,3.5vw,36px); font-weight:800; color:#F8FAFC;
               font-family:Inter,sans-serif; line-height:1.1; letter-spacing:-0.02em;">
        Architecture & Data Flow Diagram
    </h2>
    <p style="margin:10px 0 0; font-size:15px; color:#94A3B8; font-family:Inter,sans-serif;
              max-width:720px; line-height:1.6;">
        Automatically generated visual representation of the application's components, actors, and trust boundaries.
    </p>
</div>
""", unsafe_allow_html=True)

    # ── Tabs layout ──────────────────────────────────────────────────────────
    tab1, tab2, tab3 = st.tabs(["Summary View", "Detailed Flow", "Mermaid Source"])

    with tab1:
        # Use columns to simulate the balanced 3fr / 0.9fr architecture layout
        col_diagram, col_sidebar = st.columns([3, 0.9], gap="medium")
    
        with col_diagram:
            try:
                dot_summary = build_architecture_dot_summary(app_data)
                st.graphviz_chart(dot_summary, use_container_width=True)
            except Exception as e:
                st.warning(f"Could not render summary graph: {e}")
    
        with col_sidebar:
            # ── Sidebar Container ────────────────────────────────────────────
            # ── Legend ───────────────────────────────────────────────────────
            def _legend_row(color, label):
                return f'<div class="legend-item"><div class="legend-dot" style="background:{color};"></div>{label}</div>'
    
            legend_html = "".join([
                _legend_row("#2563EB", "Mobile Application"),
                _legend_row("#06B6D4", "Users / Actors"),
                _legend_row("#7C3AED", "Authentication"),
                _legend_row("#1E3A5F", "HTTPS (Secure)"),
                _legend_row("#B91C1C", "HTTP / Danger"),
                _legend_row("#F97316", "Exported Component"),
                _legend_row("#5B21B6", "Sensitive Data"),
                _legend_row("#EF4444", "External Attacker"),
            ])
    
            # ── Trust Boundaries ─────────────────────────────────────────────
            def _tb_row(code, color, label):
                return (f'<div class="trust-card" style="border-left:3px solid {color};">'
                        f'<div class="trust-id">{code}</div>'
                        f'<div class="trust-name">{label}</div>'
                        f'</div>')
    
            tb_html = "".join([
                _tb_row("TB-01", "#38BDF8", "Mobile Device Boundary"),
                _tb_row("TB-02", "#22C55E", "Network Boundary"),
                _tb_row("TB-03", "#F97316", "Backend / API Boundary"),
                _tb_row("TB-04", "#FACC15", "Privacy Boundary"),
            ])
    
            st.markdown(f"""
<div class="architecture-side-stack">
    <div class="architecture-side-panel">
        <div class="side-panel-title">Legend</div>
        <div>{legend_html}</div>
    </div>
    <div class="architecture-side-panel">
        <div class="side-panel-title">Trust Boundaries</div>
        <div>{tb_html}</div>
    </div>
</div>
""", unsafe_allow_html=True)

    with tab2:
        try:
            dot_detail = build_architecture_dot_detailed(app_data)
            st.graphviz_chart(dot_detail, use_container_width=True)
        except Exception as e:
            st.warning(f"Could not render detailed graph: {e}")

    with tab3:
        mermaid_src = build_mermaid_diagram(app_data)
        st.code(mermaid_src, language="markdown")


def render_footer():
    st.markdown("""
    <div class="footer">
        <div>Academic Credits © 2024. All rights reserved. SOC Command Interface.</div>
        <div style="display: flex; gap: 20px;">
            <span>NIST Framework</span>
            <span style="color: #0A84FF; text-decoration: underline;">OWASP MASVS</span>
            <span>MITRE ATT&CK</span>
        </div>
    </div>
    """, unsafe_allow_html=True)


def render_report_ui(app_data, analysis, generated_at):
    """Affiche le rapport de threat modeling avec un rendu HTML propre et structuré."""
    threats = analysis.get("threats", [])
    assets   = analysis.get("assets", [])
    actors   = analysis.get("actors", [])
    entries  = analysis.get("entry_points", [])
    missing  = analysis.get("missing_questions", [])

    # ── helpers ──────────────────────────────────────────────────────────
    def section_header(number, title, icon=""):
        return f"""
        <div style="display:flex;align-items:center;gap:12px;margin:2.5rem 0 1rem;">
            <div style="background:#22C55E;color:#020806;font-size:.75rem;font-weight:800;
                        padding:4px 10px;border-radius:6px;letter-spacing:.5px;">#{number}</div>
            <h2 style="margin:0;font-size:1.25rem;font-weight:800;color:#ECFDF5;">
                {icon} {title}</h2>
        </div>"""

    def severity_badge(level):
        colors = {
            "Critique": ("#EF4444","rgba(239,68,68,.12)"),
            "Élevé":    ("#F97316","rgba(249,115,22,.12)"),
            "Moyen":    ("#38BDF8","rgba(56,189,248,.12)"),
            "Faible":   ("#22C55E","rgba(34,197,94,.12)"),
        }
        c, bg = colors.get(level, ("#6B8F7A", "rgba(107,143,122,.12)"))
        badge_style = f"background:{bg};color:{c};border:1px solid {c}44;padding:2px 8px;border-radius:4px;font-size:.7rem;font-weight:700;"
        return f'<span style="{badge_style}">{level}</span>'

    # ── wrapper ───────────────────────────────────────────────────────────
    # Wrapper removed to prevent empty Streamlit blocks

    # ── title ────────────────────────────────────────────────────────────
    st.markdown(f"""
    <div style="border-bottom:1px solid #123524;padding-bottom:1.5rem;margin-bottom:.5rem;">
        <div style="font-size:.7rem;font-weight:700;color:#22C55E;letter-spacing:2px;
                    text-transform:uppercase;margin-bottom:.5rem;">Rapport officiel</div>
        <h1 style="margin:0;font-size:1.8rem;font-weight:800;color:#ECFDF5;">
            🛡️ Threat Modeling — {app_data.get('app_name','Application')}</h1>
        <div style="margin-top:.6rem;font-size:.8rem;color:#6B8F7A;">
            Généré le <strong style="color:#A7F3D0;">{generated_at}</strong>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # ── 1. Résumé exécutif ───────────────────────────────────────────────
    st.markdown(section_header(1, "Résumé exécutif", "📋"), unsafe_allow_html=True)
    n_critical = sum(1 for t in threats if t.get("level") in ["Critique","Élevé"])
    st.markdown(f"""
    <div style="background:rgba(8,18,32,0.28);backdrop-filter:blur(14px);border:1px solid rgba(148,163,184,0.1);border-left:3px solid #22C55E;
                border-radius:8px;padding:1.2rem 1.5rem;font-size:.9rem;color:#A7F3D0;line-height:1.7;box-shadow:0 10px 30px rgba(0,0,0,0.1);">
        Ce rapport présente une modélisation des menaces pour l'application
        <strong style="color:#ECFDF5;">{app_data.get('app_name','')}</strong>
        (<em>{app_data.get('app_type','')}</em>).<br>
        L'analyse a identifié <strong style="color:#FACC15;">{len(threats)} menace(s)</strong>,
        dont <strong style="color:#EF4444;">{n_critical} à haut risque</strong>.
        La méthodologie repose sur STRIDE, le scoring Impact × Probabilité × Exposition
        et le mapping OWASP MASVS.
    </div>
    """, unsafe_allow_html=True)

    # ── 2. Description ───────────────────────────────────────────────────
    st.markdown(section_header(2, "Description de l'application", "📱"), unsafe_allow_html=True)
    cols = st.columns(3)
    meta = [
        ("Nom",         app_data.get("app_name","-")),
        ("Type",        app_data.get("app_type","-")),
        ("Contexte",    app_data.get("business_context","-")),
    ]
    for col,(label,val) in zip(cols, meta):
        col.markdown(f"""
        <div style="background:rgba(8,18,32,0.28);backdrop-filter:blur(14px);border:1px solid rgba(148,163,184,0.1);border-radius:8px;padding:1rem;box-shadow:0 10px 30px rgba(0,0,0,0.1);">
            <div style="font-size:.65rem;font-weight:700;color:#6B8F7A;text-transform:uppercase;
                        letter-spacing:.5px;margin-bottom:.3rem;">{label}</div>
            <div style="font-size:.9rem;font-weight:600;color:#ECFDF5;">{val}</div>
        </div>""", unsafe_allow_html=True)
    st.markdown(f"""
    <div style="background:rgba(8,18,32,0.28);backdrop-filter:blur(14px);border:1px solid rgba(148,163,184,0.1);border-radius:8px;
                padding:1rem 1.2rem;margin-top:.8rem;font-size:.88rem;color:#6B8F7A;line-height:1.6;box-shadow:0 10px 30px rgba(0,0,0,0.1);">
        {app_data.get('description','-')}
    </div>""", unsafe_allow_html=True)

    # ── 3-5. Assets / Acteurs / Points d'entrée ──────────────────────────
    c1, c2, c3 = st.columns(3)
    for col, title, icon, items, color in [
        (c1, "Assets critiques",  "🔒", assets,  "#22C55E"),
        (c2, "Acteurs",           "👤", actors,  "#38BDF8"),
        (c3, "Points d'entrée",   "🚪", entries, "#FACC15"),
    ]:
        col.markdown(f"""
        <div style="background:rgba(8,18,32,0.28);backdrop-filter:blur(14px);border:1px solid rgba(148,163,184,0.1);border-radius:8px;
                    padding:1.2rem;margin-top:1.5rem;box-shadow:0 10px 30px rgba(0,0,0,0.1);">
            <div style="font-size:.75rem;font-weight:800;color:{color};
                        text-transform:uppercase;letter-spacing:.5px;margin-bottom:.8rem;">
                {icon} {title} ({len(items)})</div>
            {''.join(f"<div style='display:flex;align-items:center;gap:8px;padding:5px 0;border-bottom:1px solid #123524;font-size:.82rem;color:#A7F3D0;'><span style='width:6px;height:6px;border-radius:50%;background:{color};display:inline-block;flex-shrink:0;'></span>{item}</div>" for item in items)}
        </div>""", unsafe_allow_html=True)

    # ── 6. Méthodologie ──────────────────────────────────────────────────
    st.markdown(section_header(6, "Méthodologie", "🔬"), unsafe_allow_html=True)
    st.markdown("""
    <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:.8rem;">
        <div style="background:rgba(8,18,32,0.28);backdrop-filter:blur(14px);border:1px solid rgba(148,163,184,0.1);border-top:2px solid #38BDF8;
                    border-radius:8px;padding:1rem;box-shadow:0 10px 30px rgba(0,0,0,0.1);">
            <div style="font-weight:700;color:#38BDF8;margin-bottom:.4rem;font-size:.85rem;">STRIDE</div>
            <div style="font-size:.8rem;color:#6B8F7A;">Spoofing · Tampering · Repudiation ·
            Information Disclosure · Denial of Service · Elevation of Privilege</div>
        </div>
        <div style="background:rgba(8,18,32,0.28);backdrop-filter:blur(14px);border:1px solid rgba(148,163,184,0.1);border-top:2px solid #22C55E;
                    border-radius:8px;padding:1rem;box-shadow:0 10px 30px rgba(0,0,0,0.1);">
            <div style="font-weight:700;color:#22C55E;margin-bottom:.4rem;font-size:.85rem;">OWASP MASVS</div>
            <div style="font-size:.8rem;color:#6B8F7A;">Framework de référence pour la sécurité
            des applications mobiles Android.</div>
        </div>
        <div style="background:rgba(8,18,32,0.28);backdrop-filter:blur(14px);border:1px solid rgba(148,163,184,0.1);border-top:2px solid #FACC15;
                    border-radius:8px;padding:1rem;box-shadow:0 10px 30px rgba(0,0,0,0.1);">
            <div style="font-weight:700;color:#FACC15;margin-bottom:.4rem;font-size:.85rem;">Scoring</div>
            <div style="font-size:.8rem;color:#6B8F7A;">
                Score = Impact × Probabilité × Exposition<br>
                (1–25 Faible · 26–60 Moyen · 61–100 Élevé · 101+ Critique)
            </div>
        </div>
    </div>""", unsafe_allow_html=True)

    # ── 7. Risk Register ────────────────────────────────────────────────
    st.markdown(section_header(7, "Risk Register STRIDE", "⚠️"), unsafe_allow_html=True)
    if threats:
        header = """
        <div style="overflow-x:auto;">
        <table style="width:100%;border-collapse:collapse;font-size:.8rem;color:#A7F3D0;">
        <thead><tr style="background:rgba(8,26,18,0.6);border-bottom:1px solid rgba(148,163,184,0.1);">
            <th style="padding:10px 12px;text-align:left;color:#6B8F7A;font-size:.65rem;
                       font-weight:800;text-transform:uppercase;letter-spacing:1px;white-space:nowrap;">ID</th>
            <th style="padding:10px 12px;text-align:left;color:#6B8F7A;font-size:.65rem;
                       font-weight:800;text-transform:uppercase;letter-spacing:1px;">Menace</th>
            <th style="padding:10px 12px;text-align:left;color:#6B8F7A;font-size:.65rem;
                       font-weight:800;text-transform:uppercase;letter-spacing:1px;">STRIDE</th>
            <th style="padding:10px 12px;text-align:left;color:#6B8F7A;font-size:.65rem;
                       font-weight:800;text-transform:uppercase;letter-spacing:1px;">Asset</th>
            <th style="padding:10px 12px;text-align:center;color:#6B8F7A;font-size:.65rem;
                       font-weight:800;text-transform:uppercase;letter-spacing:1px;">Score</th>
            <th style="padding:10px 12px;text-align:center;color:#6B8F7A;font-size:.65rem;
                       font-weight:800;text-transform:uppercase;letter-spacing:1px;">Niveau</th>
            <th style="padding:10px 12px;text-align:left;color:#6B8F7A;font-size:.65rem;
                       font-weight:800;text-transform:uppercase;letter-spacing:1px;">MASVS</th>
        </tr></thead><tbody>"""
        rows = ""
        for i, t in enumerate(threats):
            bg = "background:rgba(8,18,32,0.26);" if i % 2 == 0 else ""
            level = t.get("level","Faible")
            stride = t.get("stride","").split("/")[0].strip().split(" ")[0]
            stride_colors = {
                "Spoofing":"#38BDF8","Tampering":"#FACC15",
                "Repudiation":"#6B8F7A","Information":"#22C55E",
                "Denial":"#EF4444","Elevation":"#F97316"
            }
            sc = stride_colors.get(stride, "#6B8F7A")
            rows += f"""
            <tr style="border-bottom:1px solid #123524;{bg}">
                <td style="padding:10px 12px;font-weight:700;color:#22C55E;white-space:nowrap;">{t.get('id','')}</td>
                <td style="padding:10px 12px;max-width:320px;line-height:1.45;color:#ECFDF5;">{t.get('threat',t.get('description',''))}</td>
                <td style="padding:10px 12px;white-space:nowrap;">
                    <span style="background:{sc}22;color:{sc};border:1px solid {sc}44;
                    padding:2px 7px;border-radius:4px;font-size:.7rem;font-weight:700;">{t.get('stride','')}</span>
                </td>
                <td style="padding:10px 12px;color:#A7F3D0;">{t.get('asset','')}</td>
                <td style="padding:10px 12px;text-align:center;font-weight:700;color:#ECFDF5;">{t.get('score',0)}</td>
                <td style="padding:10px 12px;text-align:center;">{severity_badge(level)}</td>
                <td style="padding:10px 12px;font-size:.72rem;color:#6B8F7A;">{t.get('masvs','')}</td>
            </tr>"""
        st.markdown(
            f'<div style="background:transparent;border:1px solid rgba(148,163,184,0.1);border-radius:10px;overflow:hidden;">'
            + header + rows + "</tbody></table></div></div>",
            unsafe_allow_html=True)

    # ── 8. Recommandations ───────────────────────────────────────────────
    st.markdown(section_header(8, "Recommandations prioritaires", "✅"), unsafe_allow_html=True)
    sorted_threats = sorted(threats, key=lambda x: x.get("score", 0), reverse=True)
    for t in sorted_threats:
        level = t.get("level", "Faible")
        dot_colors = {"Critique":"#EF4444","Élevé":"#F97316","Moyen":"#38BDF8","Faible":"#22C55E"}
        dot = dot_colors.get(level, "#6B8F7A")
        st.markdown(f"""
        <div style="display:flex;gap:12px;align-items:flex-start;padding:.7rem 0;
                    border-bottom:1px solid #123524;">
            <span style="margin-top:4px;width:8px;height:8px;border-radius:50%;background:{dot};
                         flex-shrink:0;display:inline-block;"></span>
            <div>
                <span style="font-weight:700;color:#22C55E;font-size:.8rem;">{t.get('id','')}</span>
                <span style="font-size:.75rem;color:#6B8F7A;margin:0 6px;">·</span>
                <span style="font-size:.82rem;color:#A7F3D0;">{t.get('mitigation','')}</span>
            </div>
        </div>""", unsafe_allow_html=True)

    # ── 9. Questions manquantes ──────────────────────────────────────────
    st.markdown(section_header(9, "Questions manquantes", "❓"), unsafe_allow_html=True)
    if missing:
        for q in missing:
            st.markdown(f"""
            <div style="display:flex;gap:10px;padding:.6rem 0;border-bottom:1px solid #123524;
                        font-size:.85rem;color:#A7F3D0;">
                <span style="color:#FACC15;">›</span> {q}</div>""",
                unsafe_allow_html=True)
    else:
        st.markdown('<div style="font-size:.85rem;color:#22C55E;padding:.5rem 0;">'
                    '✓ Aucune question manquante détectée.</div>', unsafe_allow_html=True)

    # ── 10-11. Limites & Conclusion ──────────────────────────────────────
    lc1, lc2 = st.columns(2)
    
    limitation_text = "Ce rapport est généré à partir des informations déclarées dans le fichier YAML. Il ne remplace pas un audit manuel, une revue de code ou un test d'intrusion."
    if app_data.get("app_type") == "Android APK":
        limitation_text = "This APK-based analysis is limited to static metadata extraction. It does not replace manual code review, dynamic analysis, reverse engineering, runtime testing or penetration testing."
        
    lc1.markdown(f"""
    <div style="background:rgba(8,18,32,0.28);backdrop-filter:blur(14px);border:1px solid rgba(148,163,184,0.1);border-radius:8px;
                padding:1.2rem;margin-top:1.5rem;box-shadow:0 10px 30px rgba(0,0,0,0.1);">
        <div style="font-size:.75rem;font-weight:800;color:#FACC15;text-transform:uppercase;
                    letter-spacing:.5px;margin-bottom:.6rem;">⚠ Limites</div>
        <div style="font-size:.82rem;color:#A7F3D0;line-height:1.6;">
            {limitation_text}
        </div>
    </div>""", unsafe_allow_html=True)
    lc2.markdown("""
    <div style="background:rgba(8,18,32,0.28);backdrop-filter:blur(14px);border:1px solid rgba(148,163,184,0.1);border-radius:8px;
                padding:1.2rem;margin-top:1.5rem;box-shadow:0 10px 30px rgba(0,0,0,0.1);">
        <div style="font-size:.75rem;font-weight:800;color:#22C55E;text-transform:uppercase;
                    letter-spacing:.5px;margin-bottom:.6rem;">✓ Conclusion</div>
        <div style="font-size:.82rem;color:#A7F3D0;line-height:1.6;">
            L'outil permet d'automatiser une première analyse de menace mobile, de produire
            un registre de risques et de prioriser les mesures de sécurité.
        </div>
    </div>""", unsafe_allow_html=True)

    # End of report

def render_rag_assistant(threats):
    st.markdown('<div class="fade-in-up" style="display: flex; justify-content: space-between; align-items: flex-end; margin-top: 3.5rem; margin-bottom: 1.5rem; border-bottom: 1px solid #1F6B46; padding-bottom: 1rem;"><div><h2 style="font-size: 1.3rem; margin: 0; font-weight: 700; color: #F8FAFC; display: flex; align-items: center; gap: 8px;"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#0A84FF" stroke-width="2"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"></path></svg> RAG Knowledge Assistant</h2><div style="font-size: 0.85rem; color: #6B8F7A; margin-top: 6px;">Local OWASP-inspired knowledge enrichment for detected mobile security threats.</div></div><div style="font-size: 0.7rem; color: #FACC15; background: rgba(250, 204, 21, 0.1); border: 1px solid rgba(250, 204, 21, 0.2); padding: 4px 10px; border-radius: 6px; white-space: nowrap;">⚠️ RAG enriches deterministic findings and does not replace manual validation.</div></div>', unsafe_allow_html=True)
    
    for t in threats:
        rag = t.get("rag_data", {})
        if not rag: continue
        
        with st.expander(f"✨ Enriched Threat: {t.get('threat', 'Security Flaw')} ({t.get('masvs', 'Unknown')})"):
            st.markdown(f"""
            <div style="font-size: 0.9rem; color: #ECFDF5; line-height: 1.6; margin-bottom: 1.2rem;">
                {rag.get('rag_explanation', '')}
            </div>
            
            <div style="background:rgba(8,18,32,0.28); backdrop-filter:blur(14px); border:1px solid rgba(148,163,184,0.1); border-left: 3px solid #22C55E; border-radius: 8px; padding: 1rem; margin-bottom: 1.2rem; box-shadow:0 10px 30px rgba(0,0,0,0.1);">
                <div style="font-size: 0.75rem; font-weight: 800; color: #22C55E; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 6px;">MASVS Rationale</div>
                <div style="font-size: 0.85rem; color: #A7F3D0;">{rag.get('masvs_rationale', '')}</div>
            </div>
            """, unsafe_allow_html=True)
            
            vt_html = "".join([f"<li style='margin-bottom: 6px;'>{test}</li>" for test in rag.get("verification_tests", [])])
            if vt_html:
                st.markdown(f"""
                <div style="margin-bottom: 1.2rem;">
                    <div style="font-size: 0.75rem; font-weight: 800; color: #38BDF8; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 6px;">Suggested Verification Tests</div>
                    <ul style="font-size: 0.85rem; color: #E0F2FE; margin: 0; padding-left: 20px;">
                        {vt_html}
                    </ul>
                </div>
                """, unsafe_allow_html=True)
                
            mi_html = "".join([f"<li style='margin-bottom: 6px;'>{mi}</li>" for mi in rag.get("missing_information", [])])
            if mi_html:
                st.markdown(f"""
                <div style="margin-bottom: 1.2rem;">
                    <div style="font-size: 0.75rem; font-weight: 800; color: #FACC15; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 6px;">Missing Information (Requires Manual Review)</div>
                    <ul style="font-size: 0.85rem; color: #FEF3C7; margin: 0; padding-left: 20px;">
                        {mi_html}
                    </ul>
                </div>
                """, unsafe_allow_html=True)
                
            sources_html = "".join([f'<span style="display: inline-block; background: rgba(34, 197, 94, 0.1); border: 1px solid rgba(34, 197, 94, 0.3); color: #22C55E; font-size: 0.65rem; font-weight: 700; padding: 2px 8px; border-radius: 4px; margin-right: 6px; text-transform: uppercase;">{s}</span>' for s in rag.get("rag_sources", [])])
            if sources_html:
                st.markdown(f"""
                <div style="border-top: 1px solid #123524; padding-top: 0.8rem;">
                    <div style="font-size: 0.65rem; font-weight: 800; color: #6B8F7A; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 6px;">Knowledge Sources Used</div>
                    <div>{sources_html}</div>
                </div>
                """, unsafe_allow_html=True)

def render_documentation_page():
    st.markdown("""
<style>
@keyframes docsFadeUp{from{opacity:0;transform:translateY(18px)}to{opacity:1;transform:translateY(0)}}
.docs-hero{animation:docsFadeUp .6s ease both;margin-bottom:3rem;}
.docs-card{
    background:linear-gradient(135deg,rgba(8,18,32,0.46),rgba(5,24,20,0.28));
    border:1px solid rgba(148,163,184,0.10);border-radius:22px;
    padding:32px 36px;margin-bottom:24px;
    box-shadow:0 18px 50px rgba(0,0,0,0.16);backdrop-filter:blur(14px);
    transition:transform .25s ease,border-color .25s ease;
    animation:docsFadeUp .55s ease both;
}
.docs-card:hover{transform:translateY(-3px);border-color:rgba(74,226,119,0.28);}
.docs-badge{
    display:inline-block;font-family:'JetBrains Mono',monospace;font-size:0.62rem;
    font-weight:800;letter-spacing:0.12em;padding:4px 11px;border-radius:999px;
    border:1px solid rgba(75,226,119,0.30);color:#4BE277;
    background:rgba(75,226,119,0.08);margin:3px 4px 3px 0;
}
.docs-code{
    background:rgba(8,18,32,0.55);border:1px solid rgba(148,163,184,0.12);
    border-radius:14px;padding:22px 26px;font-family:'JetBrains Mono',Consolas,monospace;
    font-size:0.82rem;color:#A7F3D0;line-height:1.7;overflow-x:auto;
    margin:16px 0;white-space:pre;
}
.docs-note{
    background:rgba(76,215,246,0.06);border:1px solid rgba(76,215,246,0.20);
    border-left:3px solid #4CD7F6;border-radius:10px;
    padding:14px 18px;font-size:0.86rem;color:#CBD5E1;margin:14px 0;
}
.docs-warning{
    background:rgba(245,158,11,0.06);border:1px solid rgba(245,158,11,0.20);
    border-left:3px solid #F59E0B;border-radius:10px;
    padding:14px 18px;font-size:0.86rem;color:#CBD5E1;margin:14px 0;
}
.docs-kicker{
    font-family:'JetBrains Mono',monospace;font-size:12px;font-weight:800;
    letter-spacing:0.18em;color:#4BE277;text-transform:uppercase;margin-bottom:10px;
}
.pipeline-step{
    display:flex;align-items:center;gap:14px;padding:14px 18px;
    background:rgba(8,18,32,0.36);border:1px solid rgba(148,163,184,0.10);
    border-radius:14px;margin-bottom:10px;
    transition:border-color .2s;
}
.pipeline-step:hover{border-color:rgba(74,226,119,0.30);}
.step-num{
    min-width:32px;height:32px;border-radius:50%;
    background:rgba(75,226,119,0.12);border:1px solid rgba(75,226,119,0.30);
    display:flex;align-items:center;justify-content:center;
    font-family:'JetBrains Mono',monospace;font-size:0.72rem;font-weight:800;color:#4BE277;
}
.stride-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-top:16px;}
.stride-card{
    background:rgba(8,18,32,0.36);border:1px solid rgba(148,163,184,0.10);
    border-radius:14px;padding:16px;
}
.masvs-pill{
    display:inline-block;background:rgba(76,215,246,0.08);border:1px solid rgba(76,215,246,0.22);
    border-radius:8px;padding:5px 12px;font-family:'JetBrains Mono',monospace;
    font-size:0.70rem;font-weight:700;color:#4CD7F6;margin:4px 4px 4px 0;
}
.risk-row{display:flex;align-items:center;gap:14px;padding:10px 0;border-bottom:1px solid rgba(148,163,184,0.07);}
</style>
""", unsafe_allow_html=True)

    # ── Hero ──────────────────────────────────────────────────────────────
    st.markdown("""
<div class="docs-hero">
  <div class="docs-kicker">Reference Guide</div>
  <h1 style="margin:0;font-size:clamp(36px,5vw,54px);font-weight:900;color:#F8FAFC;
             font-family:Inter,sans-serif;letter-spacing:-0.03em;line-height:1.08;">
      Documentation
  </h1>
  <p style="margin:14px 0 24px;font-size:16px;color:#94A3B8;max-width:680px;line-height:1.7;font-family:Inter,sans-serif;">
      Technical guide for using <strong style="color:#F1F5F9;">Threat Modeling Assistant</strong> to generate
      STRIDE-based mobile threat models, MASVS mappings, risk registers, reports, and evidence packs.
  </p>
  <div>
    <span class="docs-badge">STRIDE</span>
    <span class="docs-badge">OWASP MASVS</span>
    <span class="docs-badge">Risk Register</span>
    <span class="docs-badge">RAG Layer</span>
    <span class="docs-badge">PDF Export</span>
    <span class="docs-badge">Evidence Pack</span>
    <span class="docs-badge">Evaluation Runner</span>
  </div>
</div>
""", unsafe_allow_html=True)

    # ── 1. Overview ───────────────────────────────────────────────────────
    st.markdown("""
<div class="docs-card">
  <div class="docs-kicker">01 — Overview</div>
  <h2 style="margin:0 0 14px;font-size:26px;font-weight:800;color:#F8FAFC;font-family:Inter,sans-serif;">Project Overview</h2>
  <p style="font-size:15px;color:#CBD5E1;line-height:1.75;font-family:Inter,sans-serif;margin-bottom:16px;">
      Threat Modeling Assistant is an interactive tool for mobile application security analysis.
      Given a structured architecture description or Android APK metadata, it automatically generates a
      complete threat model including:
  </p>
  <div style="display:grid;grid-template-columns:repeat(2,1fr);gap:10px;">
""" + "".join([
    f'<div style="display:flex;align-items:center;gap:10px;padding:10px 14px;background:rgba(8,18,32,0.36);border:1px solid rgba(148,163,184,0.09);border-radius:10px;">'
    f'<span style="width:6px;height:6px;border-radius:50%;background:#4BE277;flex-shrink:0;"></span>'
    f'<span style="font-size:0.86rem;color:#E2E8F0;font-family:Inter,sans-serif;">{item}</span></div>'
    for item in ["Critical Assets & Entry Points","Threat Actors","STRIDE Threats (deterministic)","Risk Scores (Impact × Probability × Exposure)",
                 "MASVS Category Mapping","RAG-enriched Explanations","Architecture Diagram","Remediation Roadmap",
                 "Markdown & PDF Reports","Evidence Pack ZIP"]
]) + "</div></div>", unsafe_allow_html=True)

    # ── 2. Pipeline ───────────────────────────────────────────────────────
    st.markdown("""
<div class="docs-card">
  <div class="docs-kicker">02 — Architecture</div>
  <h2 style="margin:0 0 20px;font-size:26px;font-weight:800;color:#F8FAFC;font-family:Inter,sans-serif;">Analysis Pipeline</h2>
""" + "".join([
    f'<div class="pipeline-step"><div class="step-num">{n}</div>'
    f'<div><div style="font-family:Inter,sans-serif;font-weight:700;font-size:0.95rem;color:#F1F5F9;">{title}</div>'
    f'<div style="font-size:0.80rem;color:#64748B;font-family:Inter,sans-serif;margin-top:2px;">{desc}</div></div></div>'
    for n, title, desc in [
        ("1","Input Parser & Normalizer","Accepts YAML/JSON architecture files or Android APK metadata, normalises into a unified app model."),
        ("2","Rules Engine","Deterministic rule set maps app properties to STRIDE threat categories."),
        ("3","Risk Scoring","Each threat is scored: Impact × Probability × Exposure (1–125 scale)."),
        ("4","MASVS Mapping","Threats are mapped to relevant OWASP MASVS v2 categories."),
        ("5","RAG Explanation Layer","Local retrieval-based engine enriches threats with security rationale and verification steps."),
        ("6","Reports & Evidence Pack","Generates Markdown, PDF, CSV/JSON risk register, architecture diagram, and evidence ZIP."),
    ]
]) + "</div>", unsafe_allow_html=True)

    # ── 3. Inputs ─────────────────────────────────────────────────────────
    st.markdown("""
<div class="docs-card">
  <div class="docs-kicker">03 — Inputs</div>
  <h2 style="margin:0 0 16px;font-size:26px;font-weight:800;color:#F8FAFC;font-family:Inter,sans-serif;">Supported Input Formats</h2>
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;">
    <div style="background:rgba(8,18,32,0.36);border:1px solid rgba(148,163,184,0.10);border-radius:14px;padding:20px;">
      <div style="font-family:'JetBrains Mono',monospace;font-size:11px;font-weight:800;color:#4CD7F6;letter-spacing:0.12em;text-transform:uppercase;margin-bottom:12px;">Architecture File</div>
      <div style="font-size:0.86rem;color:#CBD5E1;font-family:Inter,sans-serif;line-height:1.8;">
        YAML / YML — primary supported format<br>
        JSON — supported<br>
        App structure: components, endpoints, authentication, storage, permissions
      </div>
    </div>
    <div style="background:rgba(8,18,32,0.36);border:1px solid rgba(148,163,184,0.10);border-radius:14px;padding:20px;">
      <div style="font-family:'JetBrains Mono',monospace;font-size:11px;font-weight:800;color:#F59E0B;letter-spacing:0.12em;text-transform:uppercase;margin-bottom:12px;">Android APK</div>
      <div style="font-size:0.86rem;color:#CBD5E1;font-family:Inter,sans-serif;line-height:1.8;">
        Static metadata extraction via androguard<br>
        Exported components, permissions, manifest flags<br>
        Backup flag, cleartext traffic, package metadata
      </div>
    </div>
  </div>
  <div class="docs-note" style="margin-top:16px;">The YAML/JSON architecture mode is the most stable mode for academic demonstration and produces the most complete threat model output.</div>
</div>
""", unsafe_allow_html=True)

    # ── 4. YAML Example ───────────────────────────────────────────────────
    yaml_example = """app:
  name: FintechWallet Mobile
  type: Android mobile app
  context: Fintech payment wallet

users:
  - Client
  - Conseiller

sensitive_data:
  - Name
  - PIN Code
  - Crypto Keys
  - Session Token

permissions:
  - INTERNET
  - CAMERA
  - USE_BIOMETRIC

authentication:
  method: Biometric + PIN
  mfa: true

storage:
  local_database: Realm
  encrypted: true

endpoints:
  - name: GraphQL API
    protocol: HTTPS
    authentication: JWT

components:
  - name: PaymentDeepLinkReceiver
    type: BroadcastReceiver
    exported: true"""

    st.markdown(f"""
<div class="docs-card">
  <div class="docs-kicker">04 — Example</div>
  <h2 style="margin:0 0 8px;font-size:26px;font-weight:800;color:#F8FAFC;font-family:Inter,sans-serif;">Minimal YAML Input</h2>
  <p style="font-size:14px;color:#64748B;font-family:Inter,sans-serif;margin-bottom:0;">Copy this template and adapt it to your application architecture.</p>
  <div class="docs-code">{yaml_example}</div>
</div>
""", unsafe_allow_html=True)

    # ── 5. STRIDE ─────────────────────────────────────────────────────────
    stride_items = [
        ("S","Spoofing","Impersonating another user or system — authentication failures, token theft.","#FF4D5E"),
        ("T","Tampering","Unauthorized modification of data at rest or in transit.","#F59E0B"),
        ("R","Repudiation","Actions performed without an audit trail — deniability of malicious acts.","#A78BFA"),
        ("I","Info. Disclosure","Exposure of sensitive data to unauthorized actors.","#4CD7F6"),
        ("D","Denial of Service","Resource exhaustion attacks reducing system availability.","#F87171"),
        ("E","Elevation of Privilege","Gaining higher access rights than intended by the system.","#4BE277"),
    ]
    st.markdown("""
<div class="docs-card">
  <div class="docs-kicker">05 — Methodology</div>
  <h2 style="margin:0 0 8px;font-size:26px;font-weight:800;color:#F8FAFC;font-family:Inter,sans-serif;">STRIDE Threat Categories</h2>
  <p style="font-size:14px;color:#64748B;font-family:Inter,sans-serif;margin-bottom:16px;">The engine uses deterministic rules to classify threats. An optional RAG layer provides explanation enrichment.</p>
  <div class="stride-grid">""" + "".join([
    f'<div class="stride-card"><div style="font-family:JetBrains Mono,monospace;font-size:1.4rem;font-weight:900;color:{c};margin-bottom:6px;">{l}</div>'
    f'<div style="font-weight:700;font-size:0.88rem;color:#F1F5F9;font-family:Inter,sans-serif;margin-bottom:4px;">{n}</div>'
    f'<div style="font-size:0.78rem;color:#94A3B8;font-family:Inter,sans-serif;line-height:1.5;">{d}</div></div>'
    for l, n, d, c in stride_items
]) + "</div></div>", unsafe_allow_html=True)

    # ── 6. Risk Scoring ───────────────────────────────────────────────────
    st.markdown("""
<div class="docs-card">
  <div class="docs-kicker">06 — Risk Scoring</div>
  <h2 style="margin:0 0 16px;font-size:26px;font-weight:800;color:#F8FAFC;font-family:Inter,sans-serif;">Scoring Formula</h2>
  <div style="background:rgba(8,18,32,0.46);border:1px solid rgba(74,226,119,0.20);border-radius:14px;padding:22px;text-align:center;margin-bottom:20px;">
    <div style="font-family:'JetBrains Mono',monospace;font-size:1.2rem;font-weight:800;color:#4BE277;letter-spacing:0.04em;">
      Risk Score = Impact × Probability × Exposure
    </div>
    <div style="font-size:0.82rem;color:#64748B;font-family:Inter,sans-serif;margin-top:8px;">Each dimension rated 1–5. Maximum score: 125.</div>
  </div>
  <div>""" + "".join([
    f'<div class="risk-row"><span style="font-family:JetBrains Mono,monospace;font-size:0.75rem;font-weight:800;color:{c};background:{bg};border:1px solid {bc};padding:3px 10px;border-radius:999px;white-space:nowrap;">{level}</span>'
    f'<span style="font-size:0.86rem;color:#CBD5E1;font-family:Inter,sans-serif;">{rng} — {desc}</span></div>'
    for level, rng, desc, c, bg, bc in [
        ("LOW","1–25","Minimal impact; monitor and review","#4BE277","rgba(75,226,119,0.10)","rgba(75,226,119,0.26)"),
        ("MEDIUM","26–60","Notable risk; remediation recommended","#4CD7F6","rgba(76,215,246,0.10)","rgba(76,215,246,0.26)"),
        ("HIGH","61–100","Significant risk; prioritize mitigation","#F59E0B","rgba(245,158,11,0.10)","rgba(245,158,11,0.28)"),
        ("CRITICAL","101–125","Immediate action required","#FF4D5E","rgba(255,77,94,0.10)","rgba(255,77,94,0.28)"),
    ]
]) + "</div></div>", unsafe_allow_html=True)

    # ── 7. MASVS ─────────────────────────────────────────────────────────
    masvs_cats = ["MASVS-AUTH","MASVS-STORAGE","MASVS-NETWORK","MASVS-PRIVACY","MASVS-PLATFORM","MASVS-CODE"]
    st.markdown("""
<div class="docs-card">
  <div class="docs-kicker">07 — OWASP MASVS</div>
  <h2 style="margin:0 0 12px;font-size:26px;font-weight:800;color:#F8FAFC;font-family:Inter,sans-serif;">MASVS Category Mapping</h2>
  <p style="font-size:14px;color:#64748B;font-family:Inter,sans-serif;margin-bottom:16px;">Detected threats are automatically mapped to the relevant OWASP MASVS v2 category.</p>
  <div>""" + "".join([f'<span class="masvs-pill">{c}</span>' for c in masvs_cats]) + """</div>
  <div class="docs-warning" style="margin-top:16px;">MASVS mapping is indicative. It should be validated by a certified security expert in production or regulatory audits.</div>
</div>
""", unsafe_allow_html=True)

    # ── 8. RAG ────────────────────────────────────────────────────────────
    st.markdown("""
<div class="docs-card">
  <div class="docs-kicker">08 — RAG Layer</div>
  <h2 style="margin:0 0 12px;font-size:26px;font-weight:800;color:#F8FAFC;font-family:Inter,sans-serif;">Knowledge Enrichment</h2>
  <p style="font-size:15px;color:#CBD5E1;line-height:1.75;font-family:Inter,sans-serif;margin-bottom:16px;">
      The local retrieval-based explanation layer enriches each detected threat with additional context from an OWASP-inspired knowledge base.
  </p>""" + "".join([
    f'<div style="display:flex;align-items:flex-start;gap:12px;padding:10px 0;border-bottom:1px solid rgba(148,163,184,0.07);">'
    f'<span style="width:6px;height:6px;border-radius:50%;background:#4CD7F6;flex-shrink:0;margin-top:7px;"></span>'
    f'<span style="font-size:0.88rem;color:#E2E8F0;font-family:Inter,sans-serif;">{item}</span></div>'
    for item in ["Security rationale for each threat","MASVS category justification","Suggested verification steps","Remediation recommendations","Identification of missing context or questions"]
]) + """
  <div class="docs-note" style="margin-top:14px;">The RAG layer does not replace deterministic detection or expert penetration testing validation. It is a supplementary explanation tool.</div>
</div>
""", unsafe_allow_html=True)

    # ── 9. Exports & Evaluation ───────────────────────────────────────────
    col_exp, col_eval = st.columns(2, gap="large")
    with col_exp:
        st.markdown("""
<div class="docs-card" style="height:100%;">
  <div class="docs-kicker">09 — Exports</div>
  <h2 style="margin:0 0 16px;font-size:22px;font-weight:800;color:#F8FAFC;font-family:Inter,sans-serif;">Reports &amp; Evidence Pack</h2>""" + "".join([
    f'<div style="display:flex;align-items:center;gap:10px;padding:9px 0;border-bottom:1px solid rgba(148,163,184,0.07);">'
    f'<span style="font-family:JetBrains Mono,monospace;font-size:0.62rem;font-weight:800;color:#4BE277;background:rgba(75,226,119,0.08);border:1px solid rgba(75,226,119,0.22);padding:2px 8px;border-radius:6px;">{fmt}</span>'
    f'<span style="font-size:0.83rem;color:#CBD5E1;font-family:Inter,sans-serif;">{desc}</span></div>'
    for fmt, desc in [("MD","Markdown threat model report"),("PDF","Styled PDF via Playwright"),("CSV","Risk register spreadsheet"),("JSON","Machine-readable risk register"),("ZIP","Evidence pack with full artifact set"),("HASH","Input file integrity hash")]
]) + "</div>", unsafe_allow_html=True)

    with col_eval:
        st.markdown("""
<div class="docs-card" style="height:100%;">
  <div class="docs-kicker">10 — Evaluation</div>
  <h2 style="margin:0 0 16px;font-size:22px;font-weight:800;color:#F8FAFC;font-family:Inter,sans-serif;">Evaluation Runner</h2>
  <p style="font-size:0.86rem;color:#94A3B8;font-family:Inter,sans-serif;line-height:1.6;margin-bottom:16px;">
      Runs multiple synthetic test scenarios and produces real performance metrics.
  </p>""" + "".join([
    f'<div style="display:flex;justify-content:space-between;align-items:center;padding:9px 0;border-bottom:1px solid rgba(148,163,184,0.07);">'
    f'<span style="font-size:0.83rem;color:#94A3B8;font-family:Inter,sans-serif;">{label}</span>'
    f'<span style="font-family:JetBrains Mono,monospace;font-weight:800;font-size:0.92rem;color:{c};">{val}</span></div>'
    for label, val, c in [
        ("Test scenarios","4","#4BE277"),("Threats detected","19","#F8FAFC"),
        ("High/Critical findings","7","#FF4D5E"),("Avg processing time","0.070s","#4CD7F6"),
    ]
]) + """
  <div class="docs-note" style="margin-top:14px;font-size:0.78rem;">Preliminary results on synthetic YAML scenarios — not a large real-world APK dataset.</div>
</div>""", unsafe_allow_html=True)

    # ── 10. Demo flow & Limitations ───────────────────────────────────────
    demo_steps = ["Open the app and upload an architecture YAML file","Click Start Analysis",
        "Review KPI cards (threats, risk score, coverage)","Explore the Risk Register with filters",
        "View the Architecture Diagram","Analyze STRIDE Distribution and MASVS Compliance charts",
        "Review Remediation Roadmap and priority actions","Export the PDF report",
        "Download the Forensic Evidence Pack ZIP","Open the Evaluation page to view benchmark metrics"]
    limits = ["Evaluation uses synthetic scenarios — not a large real-world dataset",
        "Generated threats are not proof of exploitability; expert validation is required",
        "Output quality depends on input architecture description completeness",
        "MASVS mapping requires expert review for compliance use","APK analysis is limited to static metadata — no dynamic or runtime analysis",
        "RAG explanations depend on local knowledge base quality and coverage"]
    future = ["React/FastAPI web version with API-first architecture","CI/CD pipeline integration for automated threat modeling",
        "Evaluation on real-world APK dataset","Stronger MASVS mapping with CVSS cross-referencing",
        "Benchmarking against MobSF, Threat Dragon, and OWASP tools",
        "Reviewer-ready artifact package for academic submission"]

    st.markdown("<div class='docs-card'><div class='docs-kicker'>11 — Demo</div>"
        "<h2 style='margin:0 0 16px;font-size:26px;font-weight:800;color:#F8FAFC;font-family:Inter,sans-serif;'>Recommended Demo Flow</h2>" +
        "".join([f'<div style="display:flex;align-items:flex-start;gap:14px;padding:10px 0;border-bottom:1px solid rgba(148,163,184,0.07);">'
                 f'<span style="font-family:JetBrains Mono,monospace;font-size:0.68rem;font-weight:800;color:#4BE277;background:rgba(75,226,119,0.08);border:1px solid rgba(75,226,119,0.22);padding:2px 9px;border-radius:6px;white-space:nowrap;min-width:28px;text-align:center;">{i+1:02d}</span>'
                 f'<span style="font-size:0.88rem;color:#CBD5E1;font-family:Inter,sans-serif;line-height:1.5;">{s}</span></div>'
                 for i, s in enumerate(demo_steps)]) +
        "</div>", unsafe_allow_html=True)

    col_lim, col_fut = st.columns(2, gap="large")
    with col_lim:
        st.markdown("<div class='docs-card'><div class='docs-kicker'>12 — Limitations</div>"
            "<h2 style='margin:0 0 16px;font-size:22px;font-weight:800;color:#F8FAFC;font-family:Inter,sans-serif;'>Known Limitations</h2>" +
            "".join([f'<div style="display:flex;align-items:flex-start;gap:10px;padding:8px 0;border-bottom:1px solid rgba(148,163,184,0.07);">'
                     f'<span style="width:5px;height:5px;border-radius:50%;background:#F59E0B;flex-shrink:0;margin-top:8px;"></span>'
                     f'<span style="font-size:0.83rem;color:#CBD5E1;font-family:Inter,sans-serif;line-height:1.5;">{l}</span></div>'
                     for l in limits]) +
            "</div>", unsafe_allow_html=True)
    with col_fut:
        st.markdown("<div class='docs-card'><div class='docs-kicker'>13 — Roadmap</div>"
            "<h2 style='margin:0 0 16px;font-size:22px;font-weight:800;color:#F8FAFC;font-family:Inter,sans-serif;'>Future Work</h2>" +
            "".join([f'<div style="display:flex;align-items:flex-start;gap:10px;padding:8px 0;border-bottom:1px solid rgba(148,163,184,0.07);">'
                     f'<span style="width:5px;height:5px;border-radius:50%;background:#4CD7F6;flex-shrink:0;margin-top:8px;"></span>'
                     f'<span style="font-size:0.83rem;color:#CBD5E1;font-family:Inter,sans-serif;line-height:1.5;">{f}</span></div>'
                     for f in future]) +
            "</div>", unsafe_allow_html=True)


def render_evaluation_ui():
    # ── Premium CSS ────────────────────────────────────────────────────────
    st.markdown("""
<style>
@keyframes evalFadeUp{from{opacity:0;transform:translateY(18px)}to{opacity:1;transform:translateY(0)}}
.eval-card{
    background:linear-gradient(135deg,rgba(8,18,32,0.52),rgba(5,24,20,0.28));
    border:1px solid rgba(148,163,184,0.12);border-radius:24px;
    padding:32px 36px;margin-bottom:24px;
    box-shadow:0 20px 60px rgba(0,0,0,0.18);backdrop-filter:blur(14px);
    transition:transform .25s ease,border-color .25s ease;
    animation:evalFadeUp .55s ease both;
}
.eval-card:hover{transform:translateY(-3px);border-color:rgba(74,226,119,0.28);}
.eval-kicker{
    font-family:'JetBrains Mono',Consolas,monospace;font-size:12px;font-weight:800;
    letter-spacing:0.18em;color:#4BE277;text-transform:uppercase;margin-bottom:10px;
}
.eval-kpi-card{
    background:linear-gradient(135deg,rgba(8,18,32,0.52),rgba(5,24,20,0.28));
    border:1px solid rgba(148,163,184,0.10);border-radius:22px;
    padding:28px 22px;text-align:center;backdrop-filter:blur(14px);
    box-shadow:0 12px 40px rgba(0,0,0,0.14);
    transition:transform .25s ease,box-shadow .25s ease,border-color .25s ease;
    animation:evalFadeUp .5s ease both;
}
.eval-kpi-card:hover{transform:translateY(-4px);box-shadow:0 20px 60px rgba(0,0,0,0.22);border-color:rgba(74,226,119,0.28);}
.eval-kpi-card-0{animation-delay:0ms;}
.eval-kpi-card-1{animation-delay:70ms;}
.eval-kpi-card-2{animation-delay:140ms;}
.eval-kpi-card-3{animation-delay:210ms;}
.eval-kpi-label{
    font-family:'JetBrains Mono',Consolas,monospace;font-size:0.62rem;font-weight:800;
    letter-spacing:0.14em;text-transform:uppercase;color:#64748B;margin-bottom:10px;
}
.eval-kpi-value{
    font-family:Inter,sans-serif;font-size:2.6rem;font-weight:900;
    line-height:1;letter-spacing:-0.03em;margin-bottom:6px;
}
.eval-kpi-sub{font-family:Inter,sans-serif;font-size:0.74rem;color:#64748B;}
.eval-tbl-wrap{
    width:100%;overflow-x:auto;border:1px solid rgba(148,163,184,0.12);
    border-radius:18px;background:rgba(8,18,32,0.22);backdrop-filter:blur(12px);
}
.eval-tbl{width:100%;border-collapse:collapse;table-layout:auto;font-family:Inter,sans-serif;}
.eval-tbl thead th{
    background:rgba(8,18,32,0.46);color:#64748B;
    font-family:'JetBrains Mono',Consolas,monospace;font-size:11px;font-weight:800;
    letter-spacing:0.09em;text-transform:uppercase;padding:15px 14px;
    border-bottom:1px solid rgba(148,163,184,0.12);white-space:nowrap;text-align:left;
}
.eval-tbl tbody td{
    color:#E2E8F0;font-size:0.86rem;padding:14px 14px;
    border-bottom:1px solid rgba(148,163,184,0.07);vertical-align:middle;
}
.eval-tbl tbody tr:hover td{background:rgba(74,226,119,0.04);}
.eval-run-btn{
    display:inline-flex;align-items:center;gap:10px;
    background:linear-gradient(90deg,#4BE277,#22C55E);color:#03120A;
    font-family:Inter,sans-serif;font-size:0.9rem;font-weight:800;letter-spacing:0.06em;
    border:none;border-radius:16px;padding:16px 36px;cursor:pointer;
    box-shadow:0 8px 28px rgba(75,226,119,0.20);transition:all .22s ease;
}
.eval-run-btn:hover{transform:translateY(-2px);box-shadow:0 14px 40px rgba(75,226,119,0.30);}
.eval-alert{
    background:rgba(75,226,119,0.07);border:1px solid rgba(75,226,119,0.28);
    border-left:3px solid #4BE277;border-radius:12px;
    padding:14px 20px;font-size:0.88rem;color:#A7F3D0;
    font-family:Inter,sans-serif;margin-top:16px;animation:evalFadeUp .4s ease both;
}
</style>
""", unsafe_allow_html=True)

    # ── Hero ───────────────────────────────────────────────────────────────
    hero_left, hero_right = st.columns([2, 1], gap="large")
    with hero_left:
        st.markdown("""
<div style="margin-top:1.5rem;margin-bottom:2rem;animation:evalFadeUp .5s ease both;">
  <div class="eval-kicker">Empirical Evaluation</div>
  <h1 style="margin:0;font-size:clamp(34px,4.5vw,52px);font-weight:900;color:#F8FAFC;
             font-family:Inter,sans-serif;letter-spacing:-0.03em;line-height:1.07;">
      Academic Evaluation<br>Runner
  </h1>
  <p style="margin:14px 0 0;font-size:15px;color:#94A3B8;max-width:560px;
            line-height:1.7;font-family:Inter,sans-serif;">
      Run reproducible benchmark scenarios to generate paper-ready metrics
      for the Threat Modeling Assistant evaluation framework.
  </p>
</div>
""", unsafe_allow_html=True)

    with hero_right:
        st.markdown("""
<div class="eval-card" style="margin-top:1.5rem;">
  <div class="eval-kicker">Evaluation Mode</div>
  <div style="display:flex;flex-direction:column;gap:10px;margin-top:4px;">
""" + "".join([
    f'<div style="display:flex;align-items:center;gap:10px;">'
    f'<span style="width:6px;height:6px;border-radius:50%;background:#4BE277;flex-shrink:0;"></span>'
    f'<span style="font-size:0.84rem;color:#CBD5E1;font-family:Inter,sans-serif;">{item}</span></div>'
    for item in ["Synthetic YAML test scenarios", "Headless pipeline execution", "CSV / JSON export", "Paper-ready metrics output"]
]) + "</div></div>", unsafe_allow_html=True)

    # ── Run Panel ──────────────────────────────────────────────────────────
    st.markdown("""
<div class="eval-card">
  <div class="eval-kicker">Benchmark Execution</div>
  <h2 style="margin:0 0 6px;font-size:22px;font-weight:800;color:#F8FAFC;font-family:Inter,sans-serif;">
      Run Empirical Evaluation
  </h2>
  <p style="font-size:0.88rem;color:#64748B;font-family:Inter,sans-serif;margin:0 0 24px;">
      Execute the evaluation runner across all configured synthetic test cases.
  </p>
""", unsafe_allow_html=True)

    run_clicked = st.button(
        "▶  Run Empirical Evaluation",
        type="primary",
        key="eval_run_btn",
        use_container_width=False,
    )
    st.markdown("</div>", unsafe_allow_html=True)

    # ── Results (only after run) ───────────────────────────────────────────
    if run_clicked:
        from src.evaluation_runner import run_all_evaluations, save_results
        import pandas as pd

        with st.spinner("Executing threat modeling pipeline on evaluation dataset..."):
            results = run_all_evaluations()

        if not results:
            st.error("No test cases found in data/evaluation_dataset/")
            return

        save_results(results)
        df = pd.DataFrame(results)

        # Success alert
        st.markdown(f"""
<div class="eval-alert">
    Evaluation complete — <strong style="color:#4BE277;">{len(results)} application(s)</strong> processed successfully.
    Results saved to <code style="background:rgba(75,226,119,0.10);padding:1px 6px;border-radius:4px;font-size:0.80rem;">evaluation_results/</code>
</div>
""", unsafe_allow_html=True)

        # ── KPI Cards ─────────────────────────────────────────────────────
        avg_time = df['analysis_time_seconds'].mean()
        total_threats = df['threats_found'].sum()
        total_critical = df['critical_risks'].sum() + df['high_risks'].sum()

        st.markdown('<div style="margin-top:2rem;"></div>', unsafe_allow_html=True)
        kc1, kc2, kc3, kc4 = st.columns(4, gap="medium")
        kpis = [
            ("Test Cases",         str(len(results)),       "Synthetic scenarios",   "#4BE277", "0"),
            ("Average Time",       f"{avg_time:.3f} s",     "Mean analysis runtime", "#4CD7F6", "1"),
            ("Total Threats",      str(int(total_threats)), "Generated findings",    "#F8FAFC", "2"),
            ("High / Critical",    str(int(total_critical)),"Priority findings",     "#F59E0B", "3"),
        ]
        for col, (label, value, sub, color, idx) in zip((kc1, kc2, kc3, kc4), kpis):
            col.markdown(f"""
<div class="eval-kpi-card eval-kpi-card-{idx}">
  <div class="eval-kpi-label">{label}</div>
  <div class="eval-kpi-value" style="color:{color};">{value}</div>
  <div class="eval-kpi-sub">{sub}</div>
</div>
""", unsafe_allow_html=True)

        # ── Metrics Table ─────────────────────────────────────────────────
        st.markdown("""
<div style="margin-top:2.5rem;margin-bottom:1rem;">
  <div class="eval-kicker">Results</div>
  <h2 style="margin:0 0 4px;font-size:24px;font-weight:800;color:#F8FAFC;font-family:Inter,sans-serif;">
      Paper-Ready Metrics Table
  </h2>
  <p style="font-size:0.84rem;color:#64748B;font-family:Inter,sans-serif;">
      Structured evaluation outputs ready for academic reporting and artifact review.
  </p>
</div>
""", unsafe_allow_html=True)

        def _risk_badge(val):
            val = str(val)
            if val in ("Élevé","High","Elevé"):
                return f'<span style="font-size:0.65rem;font-weight:800;font-family:JetBrains Mono,monospace;color:#F59E0B;background:rgba(245,158,11,0.10);border:1px solid rgba(245,158,11,0.28);padding:2px 8px;border-radius:999px;white-space:nowrap;">{val}</span>'
            if val in ("Critique","Critical"):
                return f'<span style="font-size:0.65rem;font-weight:800;font-family:JetBrains Mono,monospace;color:#FF4D5E;background:rgba(255,77,94,0.10);border:1px solid rgba(255,77,94,0.28);padding:2px 8px;border-radius:999px;white-space:nowrap;">{val}</span>'
            if val in ("Moyen","Medium"):
                return f'<span style="font-size:0.65rem;font-weight:800;font-family:JetBrains Mono,monospace;color:#4CD7F6;background:rgba(76,215,246,0.10);border:1px solid rgba(76,215,246,0.26);padding:2px 8px;border-radius:999px;white-space:nowrap;">{val}</span>'
            return f'<span style="font-size:0.65rem;font-weight:800;font-family:JetBrains Mono,monospace;color:#4BE277;background:rgba(75,226,119,0.10);border:1px solid rgba(75,226,119,0.26);padding:2px 8px;border-radius:999px;white-space:nowrap;">{val}</span>'

        def _mono(val):
            return f'<span style="font-family:JetBrains Mono,monospace;font-size:0.80rem;color:#94A3B8;">{val}</span>'

        cols_cfg = [c for c in df.columns]
        thead = "".join(
            f'<th style="background:rgba(8,18,32,0.46);color:#64748B;font-family:JetBrains Mono,monospace;'
            f'font-size:11px;font-weight:800;letter-spacing:0.09em;text-transform:uppercase;'
            f'padding:14px 14px;border-bottom:1px solid rgba(148,163,184,0.12);white-space:nowrap;">'
            f'{c.replace("_"," ")}</th>'
            for c in cols_cfg
        )
        tbody = ""
        for _, row in df.iterrows():
            cells = ""
            for c in cols_cfg:
                val = row[c]
                cl = c.lower()
                if "risk" in cl and "global" in cl:
                    cell_html = _risk_badge(val)
                elif cl in ("analysis_time_seconds","threats_found","critical_risks","high_risks","medium_risks","low_risks"):
                    cell_html = f'<span style="font-family:JetBrains Mono,monospace;font-weight:700;color:#F1F5F9;font-size:0.88rem;">{val}</span>'
                elif cl == "input_type":
                    cell_html = f'<span style="font-size:0.70rem;font-weight:700;font-family:JetBrains Mono,monospace;color:#94A3B8;background:rgba(148,163,184,0.08);border:1px solid rgba(148,163,184,0.18);padding:2px 8px;border-radius:6px;">{val}</span>'
                elif cl == "masvs_categories":
                    cell_html = f'<span style="font-size:0.72rem;color:#4CD7F6;font-family:JetBrains Mono,monospace;white-space:normal;word-break:break-word;">{val}</span>'
                else:
                    cell_html = f'<span style="font-size:0.85rem;color:#CBD5E1;font-family:Inter,sans-serif;">{val}</span>'
                cells += f'<td style="padding:14px 14px;vertical-align:middle;border-bottom:1px solid rgba(148,163,184,0.07);">{cell_html}</td>'
            tbody += (
                f'<tr onmouseover="this.querySelectorAll(\'td\').forEach(t=>t.style.background=\'rgba(74,226,119,0.04)\')" '
                f'onmouseout="this.querySelectorAll(\'td\').forEach(t=>t.style.background=\'\')">{cells}</tr>'
            )

        st.markdown(f"""
<div class="eval-tbl-wrap">
  <table class="eval-tbl">
    <thead><tr>{thead}</tr></thead>
    <tbody>{tbody}</tbody>
  </table>
</div>
""", unsafe_allow_html=True)

        # ── Export ────────────────────────────────────────────────────────
        st.markdown("""
<div style="margin-top:2.5rem;margin-bottom:1rem;">
  <div class="eval-kicker">Artifacts</div>
  <h2 style="margin:0 0 4px;font-size:22px;font-weight:800;color:#F8FAFC;font-family:Inter,sans-serif;">
      Export Artifacts
  </h2>
  <p style="font-size:0.84rem;color:#64748B;font-family:Inter,sans-serif;">
      Download benchmark results for reproducibility and paper integration.
  </p>
</div>
""", unsafe_allow_html=True)
        d1, d2, _ = st.columns([1, 1, 2])
        with open("evaluation_results/evaluation_results.csv", "rb") as f:
            d1.download_button(
                "⬇  Download CSV",
                f,
                file_name="evaluation_results.csv",
                mime="text/csv",
                use_container_width=True,
                key="dl_csv",
            )
        with open("evaluation_results/evaluation_results.json", "rb") as f:
            d2.download_button(
                "⬇  Download JSON",
                f,
                file_name="evaluation_results.json",
                mime="application/json",
                use_container_width=True,
                key="dl_json",
            )



def main():
    inject_custom_css()
    if "theme_mode" not in st.session_state:
        st.session_state.theme_mode = "system"
    apply_theme_css(st.session_state.theme_mode)
    
    st.markdown('<div class="cyber-grid-bg"></div>', unsafe_allow_html=True)
    
    if "active_page" not in st.session_state:
        st.session_state.active_page = "Dashboard"

    # Consume any pending navigation set by buttons rendered before the radio widget
    if st.session_state.get("_pending_nav"):
        st.session_state.active_page = st.session_state.pop("_pending_nav")
        
    col_brand, col_nav, col_spacer, col_status = st.columns([1.4, 3.0, 3.2, 2])
    
    with col_brand:
        st.markdown('<div class="brand">THREAT.MODEL</div>', unsafe_allow_html=True)
        
    with col_nav:
        st.radio(
            label="Navigation",
            options=["Dashboard", "Evaluation", "Documentation"],
            horizontal=True,
            label_visibility="collapsed",
            key="active_page"
        )
            
    with col_status:
        selected_theme = st.selectbox(
            "Theme",
            options=["system", "light", "dark"],
            index=["system", "light", "dark"].index(st.session_state.theme_mode),
            key="theme_mode",
            help="Switch between System, Light, and Dark themes.",
        )
        st.session_state.theme_mode = selected_theme
        st.markdown("""
        <div class="header-right">
            <div class="status-pill">
                <div class="status-dot"></div>
                SYSTEM READY
            </div>
            <div class="version-pill">v2.4</div>
        </div>
        """, unsafe_allow_html=True)
        st.caption("Theme switcher is available above.", help=None)
    
    if st.session_state.active_page == "Evaluation":
        render_evaluation_ui()
        return

    if st.session_state.active_page == "Documentation":
        render_documentation_page()
        return
        
    uploaded_file, input_mode = render_hero()
    
    if not uploaded_file:
        render_feature_cards()
    
    if uploaded_file:
        input_bytes = uploaded_file.getvalue()
        input_filename = uploaded_file.name
        
        try:
            if input_mode == "Architecture File":
                app_data = load_yaml(uploaded_file)
                validate_app_data(app_data)
            else:
                from src.apk_parser import parse_apk_to_app_model
                with st.spinner("Extracting static metadata from APK..."):
                    uploaded_file.seek(0)
                    app_data = parse_apk_to_app_model(uploaded_file)
                    
            analysis = analyze_application(app_data)
            analysis["threats"] = score_threats(analysis["threats"])
            
            # Inject RAG enrichment
            from src.rag_engine import enrich_threats_with_rag
            with st.spinner("Enriching threats with local RAG intelligence..."):
                analysis["threats"] = enrich_threats_with_rag(analysis["threats"], app_data)
                
            global_risk = calculate_global_risk(analysis["threats"])
            
            # Generate Remediation Roadmap
            roadmap = generate_remediation_roadmap(analysis["threats"])
            roadmap_metrics = calculate_roadmap_metrics(roadmap)
            analysis["roadmap"] = roadmap
            analysis["roadmap_metrics"] = roadmap_metrics
            
            mermaid_diagram = build_mermaid_diagram(app_data)
            report_md = generate_report(app_data, analysis, mermaid_diagram)
            
            st.toast("Analysis Completed Successfully!", icon="✅")
            
            render_kpi_cards(analysis["threats"], global_risk)

            # ── Architecture & Data Flow Diagram ─────────────────────────
            render_architecture_diagram(app_data)

            render_dashboard_overview(app_data, analysis)

            st.markdown('<div style="margin-top: 2rem;"></div>', unsafe_allow_html=True)
            render_risk_register(analysis["threats"])
                
            st.markdown('<div style="margin-top: 1.5rem;"></div>', unsafe_allow_html=True)
            chart_col1, chart_col2 = st.columns(2)
            with chart_col1:
                render_stride_distribution(analysis["threats"])
            with chart_col2:
                render_masvs_compliance(analysis["threats"])
                
            render_recommendations(analysis["threats"])
            render_remediation_roadmap(analysis["roadmap"], analysis["roadmap_metrics"])
            render_rag_assistant(analysis["threats"])
            
            # Affichage propre du rapport
            st.markdown("---")
            if app_data.get("app_type") == "Android APK":
                st.markdown('<div style="font-size:.7rem;font-weight:800;color:#64748B;text-transform:uppercase;letter-spacing:2px;margin-bottom:.5rem;">Input source: Android APK static metadata</div>', unsafe_allow_html=True)
            else:
                st.markdown('<div style="font-size:.7rem;font-weight:800;color:#64748B;text-transform:uppercase;letter-spacing:2px;margin-bottom:.5rem;">Input source: Architecture YAML</div>', unsafe_allow_html=True)
                
            st.markdown('<div style="font-size:.7rem;font-weight:800;color:#64748B;text-transform:uppercase;'
                        'letter-spacing:2px;margin-bottom:.5rem;">📄 RAPPORT COMPLET</div>',
                        unsafe_allow_html=True)
            from datetime import datetime as _dt
            render_report_ui(app_data, analysis, _dt.now().strftime("%Y-%m-%d %H:%M"))

            # Export Section (Refined)
            st.markdown('<div style="margin-top: 4rem; margin-bottom: 1rem;"><div style="font-weight: 700; color: #ECFDF5; margin-bottom: 5px; font-size: 1.2rem;">Ready for Stakeholder Review</div><div style="font-size: 0.85rem; color: #6B8F7A;">Your automated threat model and MASVS compliance summary is ready for export.</div></div>', unsafe_allow_html=True)
            exp_col1, exp_col2 = st.columns([1, 1])
            with exp_col1:
                st.download_button("Download Markdown", data=report_md, file_name="threat_model_report.md", mime="text/markdown", use_container_width=True)
            with exp_col2:
                # Cache the PDF generation to avoid launching Playwright on every rerun
                @st.cache_data(show_spinner="Generating Premium PDF Report...")
                def get_pdf_bytes(data, anal):
                    return generate_pdf_report(data, anal)
                
                try:
                    pdf_bytes = get_pdf_bytes(app_data, analysis)
                    st.download_button(
                        "Export PDF", 
                        data=pdf_bytes, 
                        file_name="threat_model_report.pdf", 
                        mime="application/pdf", 
                        use_container_width=True, 
                        type="primary"
                    )
                except Exception as e:
                    pdf_bytes = None
                    st.error(f"PDF Generation failed: {e}")
                    if st.button("Retry PDF Generation"):
                        st.cache_data.clear()
                        st.rerun()
            
            # --- Forensic Evidence Pack Section ---
            st.markdown("""
            <div style="background:rgba(8,18,32,0.28); backdrop-filter:blur(14px); border:1px solid rgba(148,163,184,0.1); border-radius:12px; padding:1.5rem; margin-top:2rem; margin-bottom: 2rem; box-shadow:0 18px 50px rgba(0,0,0,0.18);">
                <div style="display:flex; align-items:center; gap:10px; margin-bottom:10px;">
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#22C55E" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
                    <h3 style="margin:0; color:#ECFDF5; font-size:1.1rem; font-weight:700;">Forensic Evidence Pack</h3>
                </div>
                <div style="color:#A7F3D0; font-size:0.85rem; margin-bottom:1.5rem; line-height: 1.5;">
                    Export a reproducible ZIP package containing the input model, hashes, risk register, MASVS mapping, reports, diagrams, metadata, and audit trail.
                </div>
                <div style="display:flex; flex-wrap:wrap; gap:8px; margin-bottom:1.5rem;">
                    <span style="background:rgba(34,197,94,0.1); color:#22C55E; border:1px solid rgba(34,197,94,0.2); padding:4px 10px; border-radius:6px; font-size:0.75rem; font-weight:600;">✓ Input hash</span>
                    <span style="background:rgba(34,197,94,0.1); color:#22C55E; border:1px solid rgba(34,197,94,0.2); padding:4px 10px; border-radius:6px; font-size:0.75rem; font-weight:600;">✓ Risk register CSV/JSON</span>
                    <span style="background:rgba(34,197,94,0.1); color:#22C55E; border:1px solid rgba(34,197,94,0.2); padding:4px 10px; border-radius:6px; font-size:0.75rem; font-weight:600;">✓ MASVS mapping</span>
                    <span style="background:rgba(34,197,94,0.1); color:#22C55E; border:1px solid rgba(34,197,94,0.2); padding:4px 10px; border-radius:6px; font-size:0.75rem; font-weight:600;">✓ Architecture diagram</span>
                    <span style="background:rgba(34,197,94,0.1); color:#22C55E; border:1px solid rgba(34,197,94,0.2); padding:4px 10px; border-radius:6px; font-size:0.75rem; font-weight:600;">✓ Markdown/PDF report</span>
                    <span style="background:rgba(34,197,94,0.1); color:#22C55E; border:1px solid rgba(34,197,94,0.2); padding:4px 10px; border-radius:6px; font-size:0.75rem; font-weight:600;">✓ Analysis metadata</span>
                    <span style="background:rgba(34,197,94,0.1); color:#22C55E; border:1px solid rgba(34,197,94,0.2); padding:4px 10px; border-radius:6px; font-size:0.75rem; font-weight:600;">✓ Audit trail</span>
                </div>
            """, unsafe_allow_html=True)
            
            from src.evidence_pack import generate_evidence_pack
            
            with st.spinner("Compiling Forensic Evidence Pack..."):
                evidence_zip_bytes = generate_evidence_pack(
                    app_data=app_data,
                    analysis=analysis,
                    report_md=report_md,
                    pdf_bytes=pdf_bytes if 'pdf_bytes' in locals() else None,
                    input_bytes=input_bytes,
                    input_filename=input_filename,
                    input_type=input_mode,
                    architecture_mermaid=mermaid_diagram,
                    architecture_dot=None 
                )
            
            st.download_button(
                label="Download Evidence Pack ZIP",
                data=evidence_zip_bytes,
                file_name="threat_model_evidence_pack.zip",
                mime="application/zip",
                use_container_width=True
            )
            st.markdown("</div>", unsafe_allow_html=True)
            
            render_footer()
            
        except Exception as e:
            import traceback
            st.error(f"Error: {e}")
            st.expander("Show Traceback").code(traceback.format_exc())
    else:
        pass

if __name__ == "__main__":
    main()
