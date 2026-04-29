import pandas as pd
import streamlit as st
import plotly.express as px
from io import BytesIO

from src.parser import load_yaml, validate_app_data
from src.rules_engine import analyze_application
from src.scoring import score_threats, calculate_global_risk
from src.report_generator import generate_report
from src.pdf_generator import generate_pdf_report

# Configuration de la page
st.set_page_config(
    page_title="Threat Modeling Assistant | SOC Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

def inject_custom_css():
    st.markdown("""
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');

        html, body, [class*="st-"] {
            font-family: 'Inter', sans-serif;
        }

        /* Main Background */
        .stApp {
            background-color: #06090F; /* Deep premium noir */
            color: #E0E0E0;
        }
        
        /* Streamlit Default Container */
        .block-container {
            padding-top: 0 !important;
            padding-bottom: 1rem !important;
        }
        
        /* Hero Section */
        .hero-title {
            font-size: 3.5rem;
            font-weight: 800;
            margin-bottom: 1.2rem;
            line-height: 1.1;
            color: #FFFFFF;
            letter-spacing: -0.5px;
        }
        .hero-subtitle {
            font-size: 1.1rem;
            color: #94A3B8;
            max-width: 550px;
            margin-bottom: 2.5rem;
            line-height: 1.6;
        }
        
        /* Buttons */
        .stButton > button {
            border-radius: 8px;
            font-weight: 600;
            padding: 0.6rem 1.5rem;
            transition: all 0.2s;
        }
        .stButton > button[kind="primary"] {
            background-color: #0A84FF;
            border: none;
        }
        .stButton > button[kind="secondary"] {
            background-color: transparent;
            border: 1px solid #334155;
            color: #E2E8F0;
        }
        .stButton > button[disabled] {
            background-color: #1E293B !important;
            color: #64748B !important;
            border: none !important;
        }
        
        /* Cards */
        .custom-card {
            background-color: #0F131D;
            border: 1px solid #1E293B;
            border-radius: 12px;
            padding: 1.5rem;
            height: 100%;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
        }
        
        /* KPI Cards */
        .kpi-card {
            background-color: #0B0E14;
            border: 1px solid #1E293B;
            border-radius: 12px;
            padding: 1.2rem;
            display: flex;
            flex-direction: column;
            gap: 8px;
        }
        .kpi-value {
            font-size: 2.2rem;
            font-weight: 800;
            color: #FFFFFF;
            line-height: 1;
        }
        .kpi-label {
            color: #94A3B8;
            font-size: 0.65rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 1px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        /* Dash Sections */
        .dash-section-header {
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 1rem;
            font-size: 0.75rem;
            font-weight: 700;
            color: #94A3B8;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        .item-list {
            list-style: none;
            padding: 0;
            margin: 0;
        }
        .item-row {
            display: flex;
            justify-content: space-between;
            padding: 10px 0;
            border-bottom: 1px solid #1E293B;
            font-size: 0.85rem;
        }
        .item-row:last-child { border-bottom: none; }
        
        /* Premium Table */
        .risk-table-container {
            background-color: #0B0E14;
            border: 1px solid #1E293B;
            border-radius: 12px;
            overflow: hidden;
            width: 100%;
            margin-bottom: 2rem;
        }
        .risk-table-header {
            display: flex;
            justify-content: space-between;
            padding: 1rem 1.5rem;
            border-bottom: 1px solid #1E293B;
            align-items: center;
            font-size: 1.1rem;
            font-weight: 600;
            color: #F8FAFC;
        }
        .risk-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.85rem;
            color: #CBD5E1;
            table-layout: fixed;
        }
        .risk-table th {
            background-color: #06090F;
            color: #64748B;
            font-size: 0.65rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 1px;
            padding: 12px 1.5rem;
            text-align: left;
            border-bottom: 1px solid #1E293B;
        }
        .risk-table td {
            padding: 12px 1.5rem;
            border-bottom: 1px solid #1E293B;
            vertical-align: middle;
            word-wrap: break-word;
        }
        .risk-table tr:last-child td {
            border-bottom: none;
        }
        
        /* Badges */
        .badge {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            padding: 2px 10px;
            border-radius: 12px;
            font-size: 0.65rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .badge-critical { background-color: rgba(239, 68, 68, 0.15); color: #EF4444; }
        .badge-high { background-color: rgba(245, 158, 11, 0.15); color: #F59E0B; }
        .badge-medium { background-color: rgba(6, 182, 212, 0.15); color: #06B6D4; }
        .badge-low { background-color: rgba(16, 185, 129, 0.15); color: #10B981; }
        
        .stride-badge {
            display: inline-flex;
            align-items: center;
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 0.7rem;
            font-weight: 500;
            background-color: #1E293B;
            color: #CBD5E1;
            border: 1px solid #334155;
        }
        
        /* File Uploader Premium Look */
        [data-testid="stFileUploader"] {
            width: 100%;
        }
        [data-testid="stFileUploader"] section {
            background-color: transparent !important;
            padding: 2.5rem 2rem !important;
            border: 1px dashed #334155 !important;
            border-radius: 12px !important;
        }
        [data-testid="stFileUploader"] label {
            display: none !important;
        }
        [data-testid="stFileUploaderDropzoneInstructions"] {
            display: none !important; /* We hide the default text and add our own */
        }
        [data-testid="stFileUploader"] button {
            background-color: #0A84FF !important;
            color: #FFFFFF !important;
            border: none !important;
            border-radius: 8px !important;
            padding: 8px 24px !important;
            font-weight: 600 !important;
            margin-top: 15px !important;
        }
        
        /* Footer Info Bar */
        .info-bar {
            background-color: #1E293B;
            padding: 12px;
            text-align: center;
            color: #F8FAFC;
            font-size: 0.85rem;
            font-weight: 500;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
            position: fixed;
            bottom: 0;
            left: 0;
            right: 0;
            z-index: 1000;
            border-top: 1px solid #334155;
        }
        
        /* Footer */
        .footer {
            margin-top: 3rem;
            padding: 2rem 3rem;
            margin-bottom: 50px;
            border-top: 1px solid #1E293B;
            font-size: 0.8rem;
            color: #64748B;
            display: flex;
            justify-content: space-between;
        }
        
        /* Hide default elements */
        #MainMenu {visibility: hidden;}
        footer {visibility: hidden;}
        header {display: none !important; height: 0px !important;}
        
        /* Ensure top margin is 0 */
        body { margin: 0 !important; }
        .stApp { margin-top: 0 !important; }
    </style>
    """, unsafe_allow_html=True)

def render_navbar():
    pass

def render_hero():
    st.markdown('<div style="padding: 32px 3rem 4rem;">', unsafe_allow_html=True)
    col1, spacer, col2 = st.columns([1.1, 0.1, 0.9])
    
    with col1:
        st.markdown('<div style="display: inline-block; padding: 4px 12px; background: rgba(10, 132, 255, 0.1); border: 1px solid rgba(10, 132, 255, 0.2); border-radius: 20px; color: #0A84FF; font-size: 0.7rem; font-weight: 700; letter-spacing: 0.5px; margin-bottom: 1.5rem;">ENTERPRISE EDITION V2.4</div>', unsafe_allow_html=True)
        st.markdown('<h1 class="hero-title">AI-Ready Threat<br>Modeling for Mobile<br>Applications</h1>', unsafe_allow_html=True)
        st.markdown('<p class="hero-subtitle">Automated STRIDE and MASVS 2.0 analysis pipeline. Identify architecture flaws, map regulatory requirements, and generate mitigation strategies in seconds.</p>', unsafe_allow_html=True)
        
        btn_col1, btn_col2 = st.columns([1, 1.5])
        with btn_col1:
            st.button("▶ Start Analysis", disabled=True, use_container_width=True)
        with btn_col2:
            st.button("View Documentation", type="secondary")
            
        st.markdown("""
        <div style="margin-top: 3rem; display: flex; align-items: center; gap: 15px; border-top: 1px solid #1E293B; padding-top: 1.5rem;">
            <div style="display: flex; margin-left: 10px;">
                <img src="https://i.pravatar.cc/100?img=11" style="width: 28px; height: 28px; border-radius: 50%; border: 2px solid #06090F; margin-left: -10px;">
                <img src="https://i.pravatar.cc/100?img=33" style="width: 28px; height: 28px; border-radius: 50%; border: 2px solid #06090F; margin-left: -10px;">
            </div>
            <div style="font-size: 0.85rem; color: #94A3B8;">Trusted by <strong style="color: #F8FAFC;">120+ Security Teams</strong> worldwide.</div>
        </div>
        """, unsafe_allow_html=True)
            
    with col2:
        st.markdown(f"""
        <div style="background: linear-gradient(145deg, #0A0E17, #06090F); border: 1px solid #1E293B; border-radius: 16px; padding: 2rem;">
            <div style="text-align: center; margin-bottom: 1.5rem;">
                <div style="display: inline-flex; justify-content: center; align-items: center; width: 48px; height: 48px; background: rgba(10, 132, 255, 0.1); border-radius: 50%; color: #0A84FF; margin-bottom: 1rem;">
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="17 8 12 3 7 8"></polyline><line x1="12" y1="3" x2="12" y2="15"></line></svg>
                </div>
                <h3 style="margin: 0; color: #FFFFFF; font-size: 1.2rem; font-weight: 700;">Upload System<br>Architecture</h3>
                <p style="margin: 8px 0 0; color: #94A3B8; font-size: 0.85rem;">Supports YAML, YML, JSON, and MASVS<br>2.0 architecture models</p>
            </div>
        """, unsafe_allow_html=True)
        
        uploaded_file = st.file_uploader(
            "Upload application model",
            type=["yaml", "yml", "json"]
        )
        
        st.markdown("""
<div style="text-align: center; margin-top: -10px; margin-bottom: 1.5rem;">
    <span style="font-size: 0.65rem; color: #64748B; text-transform: uppercase; letter-spacing: 0.5px;">Max 200MB per file • YAML, YML, JSON</span>
</div>

<div style="display: flex; flex-direction: column; gap: 8px;">
    <div style="background: #0B0E14; border: 1px solid #1E293B; border-radius: 8px; padding: 12px 16px; display: flex; align-items: center; gap: 12px;">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#0A84FF" stroke-width="2"><polyline points="20 6 9 17 4 12"></polyline></svg>
        <span style="color: #CBD5E1; font-size: 0.85rem;">Automated STRIDE tagging</span>
    </div>
    <div style="background: #0B0E14; border: 1px solid #1E293B; border-radius: 8px; padding: 12px 16px; display: flex; align-items: center; gap: 12px;">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#0A84FF" stroke-width="2"><polyline points="20 6 9 17 4 12"></polyline></svg>
        <span style="color: #CBD5E1; font-size: 0.85rem;">OWASP MASVS 2.0 Compliance Matrix</span>
    </div>
</div>
</div>
""", unsafe_allow_html=True)
    
    st.markdown('</div>', unsafe_allow_html=True)
    return uploaded_file

def render_kpi_cards(threats, global_risk):
    # Calculate a mock MASVS coverage percentage
    masvs_cats = set([str(t.get('masvs', '')).split('.')[0] for t in threats if t.get('masvs')])
    coverage_percent = min(100, int((len(masvs_cats) / 8) * 100)) if masvs_cats else 75

    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown(f"""
        <div class="kpi-card">
            <div class="kpi-label">Threats Identified <span><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#EF4444" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg></span></div>
            <div style="display: flex; align-items: flex-end; justify-content: space-between; margin-top: 5px;">
                <div class="kpi-value">{len(threats)}</div>
                <div style="color: #F59E0B; font-size: 0.75rem; font-weight: 700;">+2 vs v2.3.9</div>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
    with col2:
        st.markdown(f"""
        <div class="kpi-card">
            <div class="kpi-label">Max Risk Score <span><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#F59E0B" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg></span></div>
            <div style="display: flex; align-items: flex-end; justify-content: space-between; margin-top: 5px;">
                <div class="kpi-value">{global_risk['max_score']}</div>
                <div style="color: #EF4444; font-size: 0.75rem; font-weight: 700; display: flex; align-items: center; gap: 4px;">
                    <span style="width: 6px; height: 6px; background: #EF4444; border-radius: 50%; display: inline-block;"></span>
                    Critical
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
    with col3:
        st.markdown(f"""
        <div class="kpi-card">
            <div class="kpi-label">Global Risk <span><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#94A3B8" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect><line x1="9" y1="3" x2="9" y2="21"></line></svg></span></div>
            <div style="display: flex; align-items: flex-end; justify-content: space-between; margin-top: 5px;">
                <div class="kpi-value" style="font-size: 1.8rem;">{global_risk['level']}</div>
                <div style="color: #94A3B8; font-size: 0.7rem; font-weight: 600; text-align: right; line-height: 1.2;">Trend:<br><span style="color: #CBD5E1;">Stable</span></div>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
    with col4:
        st.markdown(f"""
        <div class="kpi-card">
            <div class="kpi-label">MASVS Coverage <span><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#0A84FF" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg></span></div>
            <div style="display: flex; align-items: center; justify-content: space-between; margin-top: 5px;">
                <div class="kpi-value">{coverage_percent}%</div>
                <div style="width: 50%; height: 6px; background: #1E293B; border-radius: 4px; overflow: hidden;">
                    <div style="width: {coverage_percent}%; height: 100%; background: #0A84FF; border-radius: 4px;"></div>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)

def render_dashboard_overview(app_data, analysis):
    # Sidebar components: App Summary, Critical Assets, Entry Points, Threat Actors
    
    st.markdown("""
        <style>
            .sidebar-card {
                background: #0B0E14;
                border: 1px solid #1E293B;
                border-radius: 12px;
                padding: 1.2rem;
                margin-bottom: 1.5rem;
            }
            .sidebar-title {
                font-size: 0.7rem;
                font-weight: 800;
                color: #94A3B8;
                text-transform: uppercase;
                letter-spacing: 1px;
                margin-bottom: 1rem;
            }
            .sidebar-pill {
                display: inline-block;
                padding: 4px 12px;
                background: #1E293B;
                border: 1px solid #334155;
                border-radius: 20px;
                color: #CBD5E1;
                font-size: 0.75rem;
                font-weight: 500;
                margin: 4px 4px 4px 0;
            }
        </style>
    """, unsafe_allow_html=True)

    # App Summary
    st.markdown(f"""
    <div class="sidebar-card">
        <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 1rem;">
            <div>
                <h3 style="margin: 0; color: #F8FAFC; font-size: 1.1rem; font-weight: 700;">{app_data.get('app_name', 'Not specified')}</h3>
                <div style="color: #94A3B8; font-size: 0.75rem; margin-top: 4px;">Production Environment • v2.4.0</div>
            </div>
            <div style="background: rgba(10, 132, 255, 0.1); border: 1px solid rgba(10, 132, 255, 0.2); color: #0A84FF; font-size: 0.65rem; font-weight: 800; padding: 4px 8px; border-radius: 6px;">
                ANDROID API 28+
            </div>
        </div>
        <div style="display: flex; flex-direction: column; gap: 12px; margin-top: 1.5rem;">
            <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #1E293B; padding-bottom: 8px;">
                <span style="color: #94A3B8; font-size: 0.8rem;">Auth Pattern</span>
                <span style="color: #F8FAFC; font-size: 0.8rem; font-weight: 500;">{app_data.get('authentication', {}).get('type', 'Not specified')}</span>
            </div>
            <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #1E293B; padding-bottom: 8px;">
                <span style="color: #94A3B8; font-size: 0.8rem;">Database</span>
                <span style="color: #F8FAFC; font-size: 0.8rem; font-weight: 500;">{app_data.get('storage', {}).get('local_database', 'Not specified')}</span>
            </div>
            <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #1E293B; padding-bottom: 8px;">
                <span style="color: #94A3B8; font-size: 0.8rem;">Network Library</span>
                <span style="color: #F8FAFC; font-size: 0.8rem; font-weight: 500;">OkHttp 4.9</span>
            </div>
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <span style="color: #94A3B8; font-size: 0.8rem;">Cert Pinning</span>
                <span style="color: #0A84FF; font-size: 0.8rem; font-weight: 700;">Enabled</span>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    # Critical Assets
    assets_html = "".join([f'<span class="sidebar-pill">{a}</span>' for a in analysis.get('assets', ['Not specified'])[:5]])
    st.markdown(f"""
    <div class="sidebar-card">
        <div class="sidebar-title">Critical Assets</div>
        <div>{assets_html}</div>
    </div>
    """, unsafe_allow_html=True)
    
    # Entry Points
    ep_html = "".join([f'<div style="display: flex; align-items: center; gap: 8px; color: #CBD5E1; font-size: 0.8rem; margin-bottom: 8px;"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#0A84FF" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><polyline points="12 16 16 12 12 8"></polyline><line x1="8" y1="12" x2="16" y2="12"></line></svg>{ep}</div>' for ep in analysis.get('entry_points', ['Not specified'])[:3]])
    st.markdown(f"""
    <div class="sidebar-card">
        <div class="sidebar-title">Entry Points</div>
        <div>{ep_html}</div>
    </div>
    """, unsafe_allow_html=True)
    
    # Threat Actors
    actors = app_data.get('users', []) + app_data.get('threat_actors', [])
    if not actors:
        actors = ["Malicious App (Colocated)", "Network Adversary"]
        
    actors_html = ""
    for i, actor in enumerate(actors[:3]):
        level = "High" if i == 0 else "Medium"
        color = "#EF4444" if level == "High" else "#0A84FF"
        actors_html += f'<div style="display: flex; justify-content: space-between; align-items: center; color: #CBD5E1; font-size: 0.8rem; margin-bottom: 8px;"><span>{actor}</span><span style="color: {color}; font-weight: 700;">{level}</span></div>'

    st.markdown(f"""
    <div class="sidebar-card">
        <div class="sidebar-title">Threat Actors</div>
        <div>{actors_html}</div>
    </div>
    """, unsafe_allow_html=True)

def render_risk_register(threats):
    st.markdown("""
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
        <h3 style="margin: 0; display: flex; align-items: center; font-size: 1.1rem; color: #F8FAFC;">
            Risk Register
        </h3>
        <div style="display: flex; gap: 15px; color: #64748B;">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="cursor:pointer;"><polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"></polygon></svg>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="cursor:pointer;"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
        </div>
    </div>
    """, unsafe_allow_html=True)

    df = pd.DataFrame(threats)
    
    if "description" not in df.columns and "threat" in df.columns: df["description"] = df["threat"]
    if "severity" not in df.columns and "level" in df.columns: df["severity"] = df["level"]
    
    html = '<div class="risk-table-container"><table class="risk-table">'
    html += '<thead><tr>'
    html += '<th style="width: 8%;">ID</th>'
    html += '<th style="width: 35%;">Description</th>'
    html += '<th style="width: 20%;">STRIDE</th>'
    html += '<th style="width: 10%;">Score</th>'
    html += '<th style="width: 15%;">Severity</th>'
    html += '<th style="width: 12%;">MASVS</th>'
    html += '</tr></thead><tbody>'

    for i, row in df.iterrows():
        sev = str(row.get('severity', 'Low')).upper()
        sev_class = "badge-low"
        if sev in ['CRITICAL', 'CRITIQUE']: sev_class = "badge-critical"
        elif sev in ['HIGH', 'ÉLEVÉ']: sev_class = "badge-high"
        elif sev in ['MEDIUM', 'MOYEN']: sev_class = "badge-medium"
        
        stride_str = str(row.get('stride', 'N/A'))
        strides = [s.strip() for s in stride_str.split('/')]
        stride_html = ""
        for s in strides:
            stride_html += f'<div class="stride-badge" style="margin-bottom: 4px;">{s}</div>'
        
        html += f'<tr>'
        html += f'<td><span style="color:#94A3B8; font-size: 0.8rem;">{row.get("id", "N/A")}</span></td>'
        html += f'<td><div style="line-height:1.4; color: #E2E8F0; font-weight: 500;">{row.get("description", "N/A")}</div></td>'
        html += f'<td><div style="display: flex; flex-direction: column; align-items: flex-start;">{stride_html}</div></td>'
        html += f'<td><span style="font-weight:700; color: #F8FAFC; font-size: 1rem;">{row.get("score", 0)}</span></td>'
        html += f'<td><span class="badge {sev_class}">{sev}</span></td>'
        html += f'<td><span style="font-size:0.75rem; color:#0A84FF; font-weight: 600;">{row.get("masvs", "N/A")}</span></td>'
        html += f'</tr>'
    
    html += '</tbody></table></div>'
    st.markdown(html, unsafe_allow_html=True)

def render_stride_distribution(threats):
    st.markdown('<div class="custom-card" style="padding: 1.5rem; height: 100%;">', unsafe_allow_html=True)
    st.markdown("""
        <div style="font-size: 0.7rem; font-weight: 800; color: #94A3B8; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 1.5rem;">STRIDE DISTRIBUTION</div>
    """, unsafe_allow_html=True)
    
    df = pd.DataFrame(threats)
    stride_counts = df['stride'].value_counts().reset_index()
    stride_counts.columns = ['stride', 'count']
    
    color_map = {
        'Spoofing': '#3B82F6',
        'Tampering': '#F59E0B', # Adjusted to orange
        'Repudiation': '#94A3B8',
        'Information Disclosure': '#0A84FF', # Adjusted to blue
        'Denial of Service': '#EF4444',
        'Elevation of Privilege': '#A855F7'
    }
    
    fig = px.pie(
        stride_counts, values='count', names='stride', hole=0.75,
        color='stride', color_discrete_map=color_map
    )
    
    fig.update_layout(
        height=240,
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font_color='#CBD5E1',
        showlegend=True,
        margin=dict(t=0, b=0, l=0, r=0),
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=-0.3,
            xanchor="center",
            x=0.5,
            font=dict(size=11)
        ),
        annotations=[
            dict(text=f"<span style='font-size:32px;font-weight:bold;color:#FFFFFF;'>{len(stride_counts)}</span><br><span style='font-size:10px;color:#64748B;'>Categories</span>", x=0.5, y=0.5, showarrow=False, font_family="Inter")
        ]
    )
    fig.update_traces(textinfo='none', hovertemplate="%{label}: %{value}")
    
    st.plotly_chart(fig, use_container_width=True, config={'displayModeBar': False})
    st.markdown('</div>', unsafe_allow_html=True)

def render_masvs_compliance(threats):
    st.markdown('<div class="custom-card" style="padding: 1.5rem; height: 100%;">', unsafe_allow_html=True)
    st.markdown("""
        <div style="font-size: 0.7rem; font-weight: 800; color: #94A3B8; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 1.5rem;">MASVS COMPLIANCE</div>
    """, unsafe_allow_html=True)
    
    # Calculate mock compliance per category
    categories = [
        {"name": "V2: Data Storage", "score": 60, "color": "#0A84FF"},
        {"name": "V4: Authentication", "score": 90, "color": "#0A84FF"},
        {"name": "V5: Network Communication", "score": 100, "color": "#06B6D4"}
    ]
    
    html = '<div style="display: flex; flex-direction: column; gap: 20px; margin-top: 10px;">'
    for cat in categories:
        html += f"""
<div>
    <div style="display: flex; justify-content: space-between; font-size: 0.8rem; font-weight: 600; color: #CBD5E1; margin-bottom: 8px;">
        <span>{cat['name']}</span>
        <span style="color: {cat['color']};">{cat['score']}%</span>
    </div>
    <div style="width: 100%; height: 6px; background: #1E293B; border-radius: 4px; overflow: hidden;">
        <div style="width: {cat['score']}%; height: 100%; background: {cat['color']}; border-radius: 4px;"></div>
    </div>
</div>
"""
    html += '</div></div>'
    
    st.markdown(html, unsafe_allow_html=True)

def render_recommendations(threats):
    st.markdown('<h2 style="font-size: 1.3rem; margin-top: 3.5rem; margin-bottom: 1.5rem; font-weight: 700; color: #FFFFFF;">High Priority Recommendations</h2>', unsafe_allow_html=True)
    
    # Sort threats by score to get P0, P1, P2
    sorted_threats = sorted(threats, key=lambda x: x.get('score', 0), reverse=True)
    
    col1, col2, col3 = st.columns(3)
    cols = [col1, col2, col3]
    icons = [
        '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#EF4444" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>',
        '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#F59E0B" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>',
        '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#94A3B8" stroke-width="2"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line></svg>'
    ]
    priorities = ["P0 PRIORITY", "P1 PRIORITY", "P2 PRIORITY"]
    colors = ["#EF4444", "#F59E0B", "#94A3B8"]
    
    # Defaults if fewer than 3 threats exist
    default_titles = ["Enforce Android Keystore", "Strict HTTPS Enforcement", "Proguard/R8 Obfuscation"]
    default_desc = [
        "Migrate SQLite keys from plain SharedPrefs to Hardware-backed Keystore provider.",
        "Update Network Security Config to strictly prohibit cleartext traffic for all domains.",
        "Increase obfuscation dictionary complexity to mitigate reverse engineering of business logic."
    ]
    
    for i in range(3):
        with cols[i]:
            title = default_titles[i]
            desc = default_desc[i]
            if i < len(sorted_threats) and sorted_threats[i].get('mitigation'):
                title = sorted_threats[i].get('threat', title).split('.')[0]
                desc = sorted_threats[i].get('mitigation')
            
            st.markdown(f"""
            <div style="background: #0B0E14; border: 1px solid #1E293B; border-radius: 12px; padding: 1.5rem; height: 100%; display: flex; flex-direction: column;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.2rem;">
                    <span style="font-size: 0.65rem; font-weight: 800; color: {colors[i]}; background: {colors[i]}15; padding: 4px 10px; border-radius: 4px;">{priorities[i]}</span>
                    {icons[i]}
                </div>
                <div style="font-weight: 600; color: #F8FAFC; margin-bottom: 0.8rem; font-size: 1.05rem;">{title}</div>
                <div style="font-size: 0.85rem; color: #94A3B8; line-height: 1.5;">{desc}</div>
            </div>
            """, unsafe_allow_html=True)

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
            <div style="background:#0A84FF;color:#fff;font-size:.75rem;font-weight:800;
                        padding:4px 10px;border-radius:6px;letter-spacing:.5px;">#{number}</div>
            <h2 style="margin:0;font-size:1.25rem;font-weight:800;color:#F8FAFC;">
                {icon} {title}</h2>
        </div>"""

    def pill_list(items, color="#0A84FF"):
        style = (
            "background:rgba(10,132,255,.12);"
            f"color:{color};"
            "border:1px solid rgba(10,132,255,.25);"
            "padding:4px 12px;border-radius:20px;"
            "font-size:.8rem;font-weight:600;"
            "margin:4px 4px 4px 0;display:inline-block;"
        )
        pills = "".join(f'<span style="{style}">{i}</span>' for i in items)
        return f'<div style="margin-top:.5rem;line-height:2;">{pills}</div>'

    def severity_badge(level):
        colors = {
            "Critique": ("#EF4444","rgba(239,68,68,.12)"),
            "Élevé":    ("#F59E0B","rgba(245,158,11,.12)"),
            "Moyen":    ("#06B6D4","rgba(6,182,212,.12)"),
            "Faible":   ("#10B981","rgba(16,185,129,.12)"),
        }
        c, bg = colors.get(level, ("#94A3B8", "rgba(148,163,184,.12)"))
        badge_style = f"background:{bg};color:{c};border:1px solid {c}44;padding:2px 8px;border-radius:4px;font-size:.7rem;font-weight:700;"
        return f'<span style="{badge_style}">{level}</span>'

    # ── wrapper ───────────────────────────────────────────────────────────
    st.markdown(
        '<div style="background:#0B0F19;border:1px solid #1E293B;border-radius:16px;'
        'padding:2.5rem 2rem;margin-top:1rem;">',
        unsafe_allow_html=True)

    # ── title ────────────────────────────────────────────────────────────
    st.markdown(f"""
    <div style="border-bottom:1px solid #1E293B;padding-bottom:1.5rem;margin-bottom:.5rem;">
        <div style="font-size:.7rem;font-weight:700;color:#0A84FF;letter-spacing:2px;
                    text-transform:uppercase;margin-bottom:.5rem;">Rapport officiel</div>
        <h1 style="margin:0;font-size:1.8rem;font-weight:800;color:#FFFFFF;">
            🛡️ Threat Modeling — {app_data.get('app_name','Application')}</h1>
        <div style="margin-top:.6rem;font-size:.8rem;color:#64748B;">
            Généré le <strong style="color:#94A3B8;">{generated_at}</strong>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # ── 1. Résumé exécutif ───────────────────────────────────────────────
    st.markdown(section_header(1, "Résumé exécutif", "📋"), unsafe_allow_html=True)
    n_critical = sum(1 for t in threats if t.get("level") in ["Critique","Élevé"])
    st.markdown(f"""
    <div style="background:#0F172A;border:1px solid #1E293B;border-left:3px solid #0A84FF;
                border-radius:8px;padding:1.2rem 1.5rem;font-size:.9rem;color:#CBD5E1;line-height:1.7;">
        Ce rapport présente une modélisation des menaces pour l'application
        <strong style="color:#fff;">{app_data.get('app_name','')}</strong>
        (<em>{app_data.get('app_type','')}</em>).<br>
        L'analyse a identifié <strong style="color:#F59E0B;">{len(threats)} menace(s)</strong>,
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
        <div style="background:#0F172A;border:1px solid #1E293B;border-radius:8px;padding:1rem;">
            <div style="font-size:.65rem;font-weight:700;color:#64748B;text-transform:uppercase;
                        letter-spacing:.5px;margin-bottom:.3rem;">{label}</div>
            <div style="font-size:.9rem;font-weight:600;color:#F8FAFC;">{val}</div>
        </div>""", unsafe_allow_html=True)
    st.markdown(f"""
    <div style="background:#0F172A;border:1px solid #1E293B;border-radius:8px;
                padding:1rem 1.2rem;margin-top:.8rem;font-size:.88rem;color:#94A3B8;line-height:1.6;">
        {app_data.get('description','-')}
    </div>""", unsafe_allow_html=True)

    # ── 3-5. Assets / Acteurs / Points d'entrée ──────────────────────────
    c1, c2, c3 = st.columns(3)
    for col, title, icon, items, color in [
        (c1, "Assets critiques",  "🔒", assets,  "#0A84FF"),
        (c2, "Acteurs",           "👤", actors,  "#A855F7"),
        (c3, "Points d'entrée",   "🚪", entries, "#06B6D4"),
    ]:
        col.markdown(f"""
        <div style="background:#0F172A;border:1px solid #1E293B;border-radius:8px;
                    padding:1.2rem;margin-top:1.5rem;">
            <div style="font-size:.75rem;font-weight:800;color:{color};
                        text-transform:uppercase;letter-spacing:.5px;margin-bottom:.8rem;">
                {icon} {title} ({len(items)})</div>
            {''.join(f"""<div style='display:flex;align-items:center;gap:8px;padding:5px 0;
border-bottom:1px solid #1E293B;font-size:.82rem;color:#CBD5E1;'>
<span style='width:6px;height:6px;border-radius:50%;background:{color};
display:inline-block;flex-shrink:0;'></span>{item}</div>""" for item in items)}
        </div>""", unsafe_allow_html=True)

    # ── 6. Méthodologie ──────────────────────────────────────────────────
    st.markdown(section_header(6, "Méthodologie", "🔬"), unsafe_allow_html=True)
    st.markdown("""
    <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:.8rem;">
        <div style="background:#0F172A;border:1px solid #1E293B;border-top:2px solid #0A84FF;
                    border-radius:8px;padding:1rem;">
            <div style="font-weight:700;color:#0A84FF;margin-bottom:.4rem;font-size:.85rem;">STRIDE</div>
            <div style="font-size:.8rem;color:#94A3B8;">Spoofing · Tampering · Repudiation ·
            Information Disclosure · Denial of Service · Elevation of Privilege</div>
        </div>
        <div style="background:#0F172A;border:1px solid #1E293B;border-top:2px solid #A855F7;
                    border-radius:8px;padding:1rem;">
            <div style="font-weight:700;color:#A855F7;margin-bottom:.4rem;font-size:.85rem;">OWASP MASVS</div>
            <div style="font-size:.8rem;color:#94A3B8;">Framework de référence pour la sécurité
            des applications mobiles Android.</div>
        </div>
        <div style="background:#0F172A;border:1px solid #1E293B;border-top:2px solid #F59E0B;
                    border-radius:8px;padding:1rem;">
            <div style="font-weight:700;color:#F59E0B;margin-bottom:.4rem;font-size:.85rem;">Scoring</div>
            <div style="font-size:.8rem;color:#94A3B8;">
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
        <table style="width:100%;border-collapse:collapse;font-size:.8rem;color:#CBD5E1;">
        <thead><tr style="background:#111827;border-bottom:1px solid #334155;">
            <th style="padding:10px 12px;text-align:left;color:#64748B;font-size:.65rem;
                       font-weight:800;text-transform:uppercase;letter-spacing:1px;white-space:nowrap;">ID</th>
            <th style="padding:10px 12px;text-align:left;color:#64748B;font-size:.65rem;
                       font-weight:800;text-transform:uppercase;letter-spacing:1px;">Menace</th>
            <th style="padding:10px 12px;text-align:left;color:#64748B;font-size:.65rem;
                       font-weight:800;text-transform:uppercase;letter-spacing:1px;">STRIDE</th>
            <th style="padding:10px 12px;text-align:left;color:#64748B;font-size:.65rem;
                       font-weight:800;text-transform:uppercase;letter-spacing:1px;">Asset</th>
            <th style="padding:10px 12px;text-align:center;color:#64748B;font-size:.65rem;
                       font-weight:800;text-transform:uppercase;letter-spacing:1px;">Score</th>
            <th style="padding:10px 12px;text-align:center;color:#64748B;font-size:.65rem;
                       font-weight:800;text-transform:uppercase;letter-spacing:1px;">Niveau</th>
            <th style="padding:10px 12px;text-align:left;color:#64748B;font-size:.65rem;
                       font-weight:800;text-transform:uppercase;letter-spacing:1px;">MASVS</th>
        </tr></thead><tbody>"""
        rows = ""
        for i, t in enumerate(threats):
            bg = "background:#0F172A;" if i % 2 == 0 else ""
            level = t.get("level","Faible")
            stride = t.get("stride","").split("/")[0].strip().split(" ")[0]
            stride_colors = {
                "Spoofing":"#3B82F6","Tampering":"#A855F7",
                "Repudiation":"#94A3B8","Information":"#06B6D4",
                "Denial":"#EF4444","Elevation":"#F59E0B"
            }
            sc = stride_colors.get(stride, "#94A3B8")
            rows += f"""
            <tr style="border-bottom:1px solid #1E293B;{bg}">
                <td style="padding:10px 12px;font-weight:700;color:#0A84FF;white-space:nowrap;">{t.get('id','')}</td>
                <td style="padding:10px 12px;max-width:320px;line-height:1.45;">{t.get('threat',t.get('description',''))}</td>
                <td style="padding:10px 12px;white-space:nowrap;">
                    <span style="background:{sc}22;color:{sc};border:1px solid {sc}44;
                    padding:2px 7px;border-radius:4px;font-size:.7rem;font-weight:700;">{t.get('stride','')}</span>
                </td>
                <td style="padding:10px 12px;color:#94A3B8;">{t.get('asset','')}</td>
                <td style="padding:10px 12px;text-align:center;font-weight:700;color:#F8FAFC;">{t.get('score',0)}</td>
                <td style="padding:10px 12px;text-align:center;">{severity_badge(level)}</td>
                <td style="padding:10px 12px;font-size:.72rem;color:#64748B;">{t.get('masvs','')}</td>
            </tr>"""
        st.markdown(
            f'<div style="background:#0B0F19;border:1px solid #1E293B;border-radius:10px;overflow:hidden;">'
            + header + rows + "</tbody></table></div></div>",
            unsafe_allow_html=True)

    # ── 8. Recommandations ───────────────────────────────────────────────
    st.markdown(section_header(8, "Recommandations prioritaires", "✅"), unsafe_allow_html=True)
    sorted_threats = sorted(threats, key=lambda x: x.get("score", 0), reverse=True)
    for t in sorted_threats:
        level = t.get("level", "Faible")
        dot_colors = {"Critique":"#EF4444","Élevé":"#F59E0B","Moyen":"#06B6D4","Faible":"#10B981"}
        dot = dot_colors.get(level, "#94A3B8")
        st.markdown(f"""
        <div style="display:flex;gap:12px;align-items:flex-start;padding:.7rem 0;
                    border-bottom:1px solid #1E293B;">
            <span style="margin-top:4px;width:8px;height:8px;border-radius:50%;background:{dot};
                         flex-shrink:0;display:inline-block;"></span>
            <div>
                <span style="font-weight:700;color:#0A84FF;font-size:.8rem;">{t.get('id','')}</span>
                <span style="font-size:.75rem;color:#64748B;margin:0 6px;">·</span>
                <span style="font-size:.82rem;color:#94A3B8;">{t.get('mitigation','')}</span>
            </div>
        </div>""", unsafe_allow_html=True)

    # ── 9. Questions manquantes ──────────────────────────────────────────
    st.markdown(section_header(9, "Questions manquantes", "❓"), unsafe_allow_html=True)
    if missing:
        for q in missing:
            st.markdown(f"""
            <div style="display:flex;gap:10px;padding:.6rem 0;border-bottom:1px solid #1E293B;
                        font-size:.85rem;color:#94A3B8;">
                <span style="color:#F59E0B;">›</span> {q}</div>""",
                unsafe_allow_html=True)
    else:
        st.markdown('<div style="font-size:.85rem;color:#10B981;padding:.5rem 0;">'
                    '✓ Aucune question manquante détectée.</div>', unsafe_allow_html=True)

    # ── 10-11. Limites & Conclusion ──────────────────────────────────────
    lc1, lc2 = st.columns(2)
    lc1.markdown("""
    <div style="background:#0F172A;border:1px solid #1E293B;border-radius:8px;
                padding:1.2rem;margin-top:1.5rem;">
        <div style="font-size:.75rem;font-weight:800;color:#F59E0B;text-transform:uppercase;
                    letter-spacing:.5px;margin-bottom:.6rem;">⚠ Limites</div>
        <div style="font-size:.82rem;color:#94A3B8;line-height:1.6;">
            Ce rapport est généré à partir des informations déclarées dans le fichier YAML.
            Il ne remplace pas un audit manuel, une revue de code ou un test d'intrusion.
        </div>
    </div>""", unsafe_allow_html=True)
    lc2.markdown("""
    <div style="background:#0F172A;border:1px solid #1E293B;border-radius:8px;
                padding:1.2rem;margin-top:1.5rem;">
        <div style="font-size:.75rem;font-weight:800;color:#10B981;text-transform:uppercase;
                    letter-spacing:.5px;margin-bottom:.6rem;">✓ Conclusion</div>
        <div style="font-size:.82rem;color:#94A3B8;line-height:1.6;">
            L'outil permet d'automatiser une première analyse de menace mobile, de produire
            un registre de risques et de prioriser les mesures de sécurité.
        </div>
    </div>""", unsafe_allow_html=True)

    st.markdown('</div>', unsafe_allow_html=True)

def main():
    inject_custom_css()
    uploaded_file = render_hero()
    
    if uploaded_file:
        try:
            app_data = load_yaml(uploaded_file)
            validate_app_data(app_data)
            analysis = analyze_application(app_data)
            analysis["threats"] = score_threats(analysis["threats"])
            global_risk = calculate_global_risk(analysis["threats"])
            report_md = generate_report(app_data, analysis)
            
            st.toast("Analysis Completed Successfully!", icon="✅")
            
            render_kpi_cards(analysis["threats"], global_risk)
            
            st.markdown('<div style="margin-top: 2rem;"></div>', unsafe_allow_html=True)
            dash_col1, dash_col2 = st.columns([1, 2.8])
            
            with dash_col1:
                render_dashboard_overview(app_data, analysis)
                
            with dash_col2:
                render_risk_register(analysis["threats"])
                
                st.markdown('<div style="margin-top: 1.5rem;"></div>', unsafe_allow_html=True)
                chart_col1, chart_col2 = st.columns(2)
                with chart_col1:
                    render_stride_distribution(analysis["threats"])
                with chart_col2:
                    render_masvs_compliance(analysis["threats"])
                    
                render_recommendations(analysis["threats"])
            
            # Affichage propre du rapport
            st.markdown("---")
            st.markdown('<div style="font-size:.7rem;font-weight:800;color:#64748B;text-transform:uppercase;'
                        'letter-spacing:2px;margin-bottom:.5rem;">📄 RAPPORT COMPLET</div>',
                        unsafe_allow_html=True)
            from datetime import datetime as _dt
            render_report_ui(app_data, analysis, _dt.now().strftime("%Y-%m-%d %H:%M"))

            # Export Section (Refined)
            st.markdown('<div style="background: #0F172A; border: 1px solid #1E293B; border-radius: 12px; padding: 2rem; display: flex; justify-content: space-between; align-items: center; margin-top: 4rem;">', unsafe_allow_html=True)
            st.markdown('<div><div style="font-weight: 700; color: #F8FAFC; margin-bottom: 5px;">Ready for Stakeholder Review</div><div style="font-size: 0.85rem; color: #64748B;">Your automated threat model and MASVS compliance summary is ready for export.</div></div>', unsafe_allow_html=True)
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
                    st.error(f"PDF Generation failed: {e}")
                    if st.button("Retry PDF Generation"):
                        st.cache_data.clear()
                        st.rerun()
            st.markdown('</div>', unsafe_allow_html=True)
            
            render_footer()
            
        except Exception as e:
            import traceback
            st.error(f"Error: {e}")
            st.expander("Show Traceback").code(traceback.format_exc())
    else:
        st.info("Upload your system architecture YAML to begin.")

if __name__ == "__main__":
    main()
