"""
architecture_graph.py – Summary & Detailed Graphviz + Mermaid builders.
"""
from __future__ import annotations
import re

# ── palette ──────────────────────────────────────────────────────────────────
C = dict(
    bg="#0B0F19", app="#1D4ED8", app_f="#FFF", user="#0891B2", user_f="#FFF",
    auth="#7C3AED", auth_f="#FFF", stor="#1E3A5F", stor_f="#93C5FD",
    perm_d="#7C2D12", perm_df="#FCA5A5", perm_s="#064E3B", perm_sf="#6EE7B7",
    ep_s="#14532D", ep_sf="#86EFAC", ep_d="#7C2D12", ep_df="#FCA5A5",
    comp_n="#1E293B", comp_nf="#94A3B8", comp_e="#78350F", comp_ef="#FCD34D",
    sens="#4C1D95", sens_f="#F0ABFC", att="#991B1B", att_f="#FCA5A5",
    grp="#0F172A", e_norm="#334155", e_https="#22C55E", e_http="#EF4444",
    e_int="#3B82F6", e_warn="#F97316",
)

DANGEROUS_PERMS = {
    "android.permission.READ_CONTACTS", "android.permission.WRITE_CONTACTS",
    "android.permission.READ_SMS", "android.permission.SEND_SMS",
    "android.permission.CAMERA", "android.permission.RECORD_AUDIO",
    "android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.READ_EXTERNAL_STORAGE", "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.READ_PHONE_STATE", "android.permission.CALL_PHONE",
    "android.permission.USE_BIOMETRIC", "android.permission.GET_ACCOUNTS",
    "android.permission.ACCESS_BACKGROUND_LOCATION", "android.permission.BODY_SENSORS",
    "android.permission.READ_CALL_LOG", "android.permission.WRITE_CALL_LOG",
    "android.permission.RECEIVE_SMS", "android.permission.RECEIVE_MMS",
    "android.permission.READ_CALENDAR", "android.permission.WRITE_CALENDAR",
    "android.permission.BLUETOOTH_SCAN", "android.permission.BLUETOOTH_CONNECT",
}

def _sid(t: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]", "_", str(t))

def _sl(t: str, mx: int = 24) -> str:
    t = str(t)
    return t if len(t) <= mx else t[:mx-3] + "..."

def _is_https(u: str) -> bool:
    return str(u).lower().startswith("https")

# ── GRAPH DEFAULTS ───────────────────────────────────────────────────────────
_GRAPH_COMPACT = (
    f'graph [bgcolor="{C["bg"]}" rankdir=LR splines=true overlap=false '
    f'nodesep=0.4 ranksep=0.6 margin="0.05" pad="0.1" fontname="Arial"];'
)
_NODE_COMPACT = 'node [shape=box style="rounded,filled" fontname="Arial" fontsize=9 margin="0.08,0.04" height=0.3];'
_EDGE_COMPACT = 'edge [fontsize=8 arrowsize=0.6 fontname="Arial"];'


def _extract(app_data):
    return (
        app_data.get("app_name", "Mobile App"),
        app_data.get("users", []),
        app_data.get("permissions", []),
        app_data.get("endpoints", []),
        app_data.get("components", []),
        app_data.get("sensitive_data", []),
        app_data.get("authentication", {}),
        app_data.get("storage", {}),
    )


# ═════════════════════════════════════════════════════════════════════════════
#  SUMMARY DOT (compact, max ~12 nodes)
# ═════════════════════════════════════════════════════════════════════════════

def build_architecture_dot_summary(app_data: dict) -> str:
    name, users, perms, eps, comps, sens, auth, stor = _extract(app_data)
    L, E = [], []

    def n(nid, lbl, fill, fc, **kw):
        extra = " ".join(f'{k}={v}' for k, v in kw.items())
        L.append(f'    {nid} [label="{lbl}" fillcolor="{fill}" fontcolor="{fc}" {extra}];')

    def e(a, b, lbl="", col="", sty="solid"):
        col = col or C["e_norm"]
        la = f'label="{lbl}" ' if lbl else ""
        E.append(f'    {a} -> {b} [{la}color="{col}" fontcolor="{col}" style={sty}];')

    L.append("digraph arch {")
    L.append(f"    {_GRAPH_COMPACT}")
    L.append(f"    {_NODE_COMPACT}")
    L.append(f"    {_EDGE_COMPACT}")
    L.append("")

    # Users (collapsed)
    if users:
        lbl = "\\n".join(_sl(u, 18) for u in users[:3])
        if len(users) > 3:
            lbl += f"\\n+ {len(users)-3} more"
        n("users", lbl, C["user"], C["user_f"], shape="ellipse")

    # App
    n("app", _sl(name, 20), C["app"], C["app_f"], penwidth="2", fontsize="10")

    # Auth
    at = auth.get("type", "?") if isinstance(auth, dict) else "?"
    mfa = "MFA ON" if (isinstance(auth, dict) and auth.get("mfa")) else "No MFA"
    n("auth", f"Auth\\n{_sl(at,16)}\\n{mfa}", C["auth"], C["auth_f"])

    # Storage
    db = stor.get("local_database", "?") if isinstance(stor, dict) else "?"
    bk = stor.get("allowBackup", "?") if isinstance(stor, dict) else "?"
    bk_t = "Backup ON" if bk is True else ("Backup OFF" if bk is False else "Backup ?")
    n("storage", f"Storage\\n{_sl(str(db),16)}\\n{bk_t}", C["stor"], C["stor_f"], shape="cylinder")

    # Dangerous perms (collapsed)
    dp = [p for p in perms if p in DANGEROUS_PERMS]
    if dp:
        lbl = "\\n".join(_sl(p.replace("android.permission.", ""), 18) for p in dp[:3])
        if len(dp) > 3:
            lbl += f"\\n+ {len(dp)-3} more"
        n("d_perms", f"Sensitive Perms\\n{lbl}", C["perm_d"], C["perm_df"])

    # Endpoints (collapsed)
    if eps:
        https_n = sum(1 for ep in eps if _is_https(ep))
        http_n = len(eps) - https_n
        parts = []
        if https_n: parts.append(f"{https_n} HTTPS")
        if http_n: parts.append(f"{http_n} HTTP")
        lbl = "API Endpoints\\n" + " / ".join(parts)
        fill = C["ep_s"] if http_n == 0 else C["ep_d"]
        fc = C["ep_sf"] if http_n == 0 else C["ep_df"]
        n("endpoints", lbl, fill, fc)

    # Exported components (collapsed)
    exported = [c for c in comps if c.get("exported")]
    if exported:
        lbl = f"Exported Components\\n({len(exported)} found)"
        n("exp_comps", lbl, C["comp_e"], C["comp_ef"])

    # Sensitive data (collapsed)
    if sens:
        lbl = "\\n".join(_sl(str(s), 18) for s in sens[:3])
        if len(sens) > 3:
            lbl += f"\\n+ {len(sens)-3} more"
        n("sens_data", f"Sensitive Data\\n{lbl}", C["sens"], C["sens_f"])

    # Attacker
    n("attacker", "Attacker\\n(External)", C["att"], C["att_f"], shape="octagon")

    # Edges
    if users: e("users", "app", "uses", C["e_int"])
    e("app", "auth", "authenticates", C["e_int"])
    e("app", "storage", "reads/writes", C["e_int"])
    if dp: e("app", "d_perms", "requests", C["e_warn"], "dashed")
    if eps: e("app", "endpoints", "HTTPS" if http_n == 0 else "HTTP+S", C["e_https"] if http_n == 0 else C["e_http"])
    if exported: e("app", "exp_comps", "exposes", C["e_warn"], "dashed")
    if sens: e("storage", "sens_data", "stores", C["e_warn"], "dashed")
    e("attacker", "app", "targets", C["e_http"], "dashed")
    if exported: e("attacker", "exp_comps", "exploits", C["e_http"], "dashed")
    if eps and http_n > 0: e("attacker", "endpoints", "intercepts", C["e_http"], "dashed")

    L.append("")
    L.extend(E)
    L.append("}")
    return "\n".join(L)


# ═════════════════════════════════════════════════════════════════════════════
#  DETAILED DOT (full nodes, capped)
# ═════════════════════════════════════════════════════════════════════════════

def build_architecture_dot_detailed(app_data: dict) -> str:
    name, users, perms, eps, comps, sens, auth, stor = _extract(app_data)
    L, E = [], []

    def e(a, b, lbl="", col="", sty="solid"):
        col = col or C["e_norm"]
        la = f'label="{lbl}" ' if lbl else ""
        E.append(f'    {a} -> {b} [{la}color="{col}" fontcolor="{col}" style={sty}];')

    L.append("digraph arch_detail {")
    L.append(f"    {_GRAPH_COMPACT}")
    L.append(f"    {_NODE_COMPACT}")
    L.append(f"    {_EDGE_COMPACT}")
    L.append("")

    # Attacker
    L.append('    subgraph cluster_ext {')
    L.append(f'        label="External" fontcolor="#EF4444" fontname="Arial" fontsize=9 color="#7F1D1D" style="dashed,rounded" bgcolor="{C["grp"]}";')
    L.append(f'        attacker [label="Attacker" shape=octagon fillcolor="{C["att"]}" fontcolor="{C["att_f"]}"];')
    L.append('    }')
    L.append("")

    # Users
    if users:
        L.append('    subgraph cluster_users {')
        L.append(f'        label="Users" fontcolor="{C["user"]}" fontname="Arial" fontsize=9 color="{C["user"]}" style="dashed,rounded" bgcolor="{C["grp"]}";')
        for u in users[:5]:
            uid = _sid(f"u_{u}")
            L.append(f'        {uid} [label="{_sl(u,18)}" shape=ellipse fillcolor="{C["user"]}" fontcolor="{C["user_f"]}"];')
        if len(users) > 5:
            L.append(f'        u_more [label="+ {len(users)-5} more" fillcolor="{C["grp"]}" fontcolor="#64748B" style="dashed"];')
        L.append('    }')
        L.append("")

    # App cluster
    app_id = "app"
    at = auth.get("type", "?") if isinstance(auth, dict) else "?"
    mfa = "MFA ON" if (isinstance(auth, dict) and auth.get("mfa")) else "No MFA"
    db = stor.get("local_database", "?") if isinstance(stor, dict) else "?"
    bk = stor.get("allowBackup", "?") if isinstance(stor, dict) else "?"
    bk_t = "Backup ON" if bk is True else ("Backup OFF" if bk is False else "Backup ?")

    L.append('    subgraph cluster_app {')
    L.append(f'        label="Mobile Application" fontcolor="{C["app_f"]}" fontname="Arial" fontsize=9 color="{C["app"]}" style="rounded" bgcolor="#0D1B3E";')
    L.append(f'        {app_id} [label="{_sl(name,20)}" fillcolor="{C["app"]}" fontcolor="{C["app_f"]}" penwidth=2 fontsize=10];')
    L.append(f'        auth [label="Auth\\n{_sl(at,14)}\\n{mfa}" fillcolor="{C["auth"]}" fontcolor="{C["auth_f"]}"];')
    L.append(f'        storage [label="Storage\\n{_sl(str(db),14)}\\n{bk_t}" shape=cylinder fillcolor="{C["stor"]}" fontcolor="{C["stor_f"]}"];')
    L.append('    }')
    L.append("")
    e(app_id, "auth", "authenticates", C["e_int"])
    e(app_id, "storage", "reads/writes", C["e_int"])

    # Components
    if comps:
        L.append('    subgraph cluster_comps {')
        L.append(f'        label="Components" fontcolor="{C["comp_nf"]}" fontname="Arial" fontsize=9 color="#334155" style="dashed,rounded" bgcolor="{C["grp"]}";')
        for c in comps[:6]:
            cn = c.get("name", "?")
            ex = c.get("exported", False)
            cid = _sid(f"c_{cn}")
            fill = C["comp_e"] if ex else C["comp_n"]
            fc = C["comp_ef"] if ex else C["comp_nf"]
            tag = "EXPORTED" if ex else c.get("type", "")
            L.append(f'        {cid} [label="{_sl(cn,18)}\\n{tag}" fillcolor="{fill}" fontcolor="{fc}"];')
        if len(comps) > 6:
            L.append(f'        c_more [label="+ {len(comps)-6} more" fillcolor="{C["grp"]}" fontcolor="#64748B" style="dashed"];')
        L.append('    }')
        L.append("")
        for c in comps[:6]:
            cid = _sid(f"c_{c.get('name','?')}")
            ex = c.get("exported", False)
            e(app_id, cid, "exposes" if ex else "uses", C["e_warn"] if ex else C["e_norm"], "dashed" if ex else "solid")

    # Permissions
    dp = [p for p in perms if p in DANGEROUS_PERMS][:5]
    sp = [p for p in perms if p not in DANGEROUS_PERMS][:3]
    if dp or sp:
        L.append('    subgraph cluster_perms {')
        L.append(f'        label="Permissions" fontcolor="{C["perm_df"]}" fontname="Arial" fontsize=9 color="#431407" style="dashed,rounded" bgcolor="{C["grp"]}";')
        for p in dp:
            pid = _sid(f"p_{p}")
            L.append(f'        {pid} [label="DANGER\\n{_sl(p.replace("android.permission.",""),18)}" fillcolor="{C["perm_d"]}" fontcolor="{C["perm_df"]}"];')
        for p in sp:
            pid = _sid(f"p_{p}")
            L.append(f'        {pid} [label="{_sl(p.replace("android.permission.",""),18)}" fillcolor="{C["perm_s"]}" fontcolor="{C["perm_sf"]}"];')
        rem = len(perms) - len(dp) - len(sp)
        if rem > 0:
            L.append(f'        p_more [label="+ {rem} more" fillcolor="{C["grp"]}" fontcolor="#64748B" style="dashed"];')
        L.append('    }')
        L.append("")
        for p in dp:
            e(app_id, _sid(f"p_{p}"), "requests", C["e_warn"], "dashed")
        for p in sp:
            e(app_id, _sid(f"p_{p}"), "requests", C["e_norm"])

    # Sensitive data
    if sens:
        L.append('    subgraph cluster_sens {')
        L.append(f'        label="Sensitive Data" fontcolor="{C["sens_f"]}" fontname="Arial" fontsize=9 color="#6B21A8" style="dashed,rounded" bgcolor="{C["grp"]}";')
        for s in sens[:5]:
            sid = _sid(f"s_{s}")
            L.append(f'        {sid} [label="{_sl(str(s),20)}" fillcolor="{C["sens"]}" fontcolor="{C["sens_f"]}"];')
        if len(sens) > 5:
            L.append(f'        s_more [label="+ {len(sens)-5} more" fillcolor="{C["grp"]}" fontcolor="#64748B" style="dashed"];')
        L.append('    }')
        L.append("")
        for s in sens[:5]:
            e("storage", _sid(f"s_{s}"), "stores", C["e_warn"], "dashed")

    # Endpoints
    if eps:
        L.append('    subgraph cluster_eps {')
        L.append(f'        label="Endpoints" fontcolor="{C["ep_sf"]}" fontname="Arial" fontsize=9 color="#14532D" style="dashed,rounded" bgcolor="{C["grp"]}";')
        for ep in eps[:5]:
            eid = _sid(f"e_{ep}")
            https = _is_https(ep)
            fill = C["ep_s"] if https else C["ep_d"]
            fc = C["ep_sf"] if https else C["ep_df"]
            proto = "HTTPS" if https else "HTTP"
            L.append(f'        {eid} [label="{proto}\\n{_sl(ep,24)}" fillcolor="{fill}" fontcolor="{fc}"];')
        if len(eps) > 5:
            L.append(f'        e_more [label="+ {len(eps)-5} more" fillcolor="{C["grp"]}" fontcolor="#64748B" style="dashed"];')
        L.append('    }')
        L.append("")
        for ep in eps[:5]:
            eid = _sid(f"e_{ep}")
            https = _is_https(ep)
            e(app_id, eid, "HTTPS" if https else "HTTP", C["e_https"] if https else C["e_http"])

    # User edges
    for u in users[:5]:
        e(_sid(f"u_{u}"), app_id, "uses", C["e_int"])

    # Attacker edges
    e("attacker", app_id, "targets", C["e_http"], "dashed")
    if eps:
        e("attacker", _sid(f"e_{eps[0]}"), "intercepts", C["e_http"], "dashed")
    for c in [c for c in comps if c.get("exported")][:2]:
        e("attacker", _sid(f"c_{c['name']}"), "exploits", C["e_http"], "dashed")

    L.append("")
    L.extend(E)
    L.append("}")
    return "\n".join(L)


# Keep backward compat alias
build_architecture_dot = build_architecture_dot_summary


# ═════════════════════════════════════════════════════════════════════════════
#  MERMAID
# ═════════════════════════════════════════════════════════════════════════════

def build_mermaid_diagram(app_data: dict) -> str:
    name, users, perms, eps, comps, sens, auth, stor = _extract(app_data)
    L = ["```mermaid", "flowchart LR"]
    L += [
        "    classDef app fill:#1D4ED8,stroke:#3B82F6,color:#fff",
        "    classDef user fill:#0891B2,stroke:#22D3EE,color:#fff",
        "    classDef auth fill:#7C3AED,stroke:#A78BFA,color:#fff",
        "    classDef storage fill:#1E3A5F,stroke:#3B82F6,color:#93C5FD",
        "    classDef permD fill:#7C2D12,stroke:#EF4444,color:#FCA5A5",
        "    classDef epS fill:#14532D,stroke:#22C55E,color:#86EFAC",
        "    classDef epD fill:#7C2D12,stroke:#EF4444,color:#FCA5A5",
        "    classDef compE fill:#78350F,stroke:#F59E0B,color:#FCD34D",
        "    classDef sens fill:#4C1D95,stroke:#A855F7,color:#F0ABFC",
        "    classDef att fill:#991B1B,stroke:#EF4444,color:#FCA5A5",
    ]

    aid = _sid(f"app_{name}")
    L.append(f'    {aid}["{_sl(name,20)}"]:::app')

    at = auth.get("type", "?") if isinstance(auth, dict) else "?"
    mfa = "MFA ON" if (isinstance(auth, dict) and auth.get("mfa")) else "No MFA"
    L.append(f'    auth_n["Auth - {_sl(at,14)} - {mfa}"]:::auth')
    L.append(f'    {aid} --> |authenticates| auth_n')

    db = stor.get("local_database", "?") if isinstance(stor, dict) else "?"
    bk = stor.get("allowBackup", "?") if isinstance(stor, dict) else "?"
    bk_t = "Backup ON" if bk is True else ("Backup OFF" if bk is False else "Backup ?")
    L.append(f'    stor_n[("Storage - {_sl(str(db),14)} - {bk_t}")]:::storage')
    L.append(f'    {aid} --> |reads/writes| stor_n')

    L.append('    att_n["Attacker"]:::att')
    L.append(f'    att_n -.-> |targets| {aid}')

    for u in users[:3]:
        uid = _sid(f"u_{u}")
        L.append(f'    {uid}["{_sl(u,16)}"]:::user')
        L.append(f'    {uid} --> |uses| {aid}')

    for s in sens[:3]:
        sid = _sid(f"s_{s}")
        L.append(f'    {sid}["{_sl(str(s),16)}"]:::sens')
        L.append(f'    stor_n -.-> |stores| {sid}')

    for ep in eps[:4]:
        eid = _sid(f"e_{ep}")
        https = _is_https(ep)
        cls = "epS" if https else "epD"
        proto = "HTTPS" if https else "HTTP"
        L.append(f'    {eid}["{proto} - {_sl(ep,22)}"]:::{cls}')
        L.append(f'    {aid} --> |{proto}| {eid}')

    dp = [p for p in perms if p in DANGEROUS_PERMS][:3]
    for p in dp:
        pid = _sid(f"p_{p}")
        L.append(f'    {pid}["DANGER - {_sl(p.replace("android.permission.",""),18)}"]:::permD')
        L.append(f'    {aid} -.-> |requests| {pid}')

    for c in [c for c in comps if c.get("exported")][:3]:
        cid = _sid(f"c_{c['name']}")
        L.append(f'    {cid}["{_sl(c["name"],16)} EXPORTED"]:::compE')
        L.append(f'    {aid} --> |exposes| {cid}')
        L.append(f'    att_n -.-> |exploits| {cid}')

    L.append("```")
    return "\n".join(L)


# ═════════════════════════════════════════════════════════════════════════════
#  HTML FALLBACK FOR PDF
# ═════════════════════════════════════════════════════════════════════════════

def build_architecture_html_for_pdf(app_data: dict) -> str:
    """Generates a static HTML flow diagram for PDF embedding."""
    name, users, perms, eps, comps, sens, auth, stor = _extract(app_data)
    at = auth.get("type", "?") if isinstance(auth, dict) else "?"
    mfa = "MFA" if (isinstance(auth, dict) and auth.get("mfa")) else "No MFA"
    db = stor.get("local_database", "?") if isinstance(stor, dict) else "?"
    bk = stor.get("allowBackup", "?") if isinstance(stor, dict) else "?"
    bk_t = "Backup ON" if bk is True else ("OFF" if bk is False else "?")
    dp = [p.replace("android.permission.","") for p in perms if p in DANGEROUS_PERMS][:4]
    exported = [c for c in comps if c.get("exported")]
    https_n = sum(1 for e in eps if _is_https(e))
    http_n = len(eps) - https_n

    def _box(label, sub, color, border):
        return (
            f'<div style="background:{color};border:2px solid {border};border-radius:8px;'
            f'padding:8px 12px;text-align:center;min-width:120px;">'
            f'<div style="font-weight:700;font-size:9pt;color:#fff;">{label}</div>'
            f'<div style="font-size:7pt;color:#CBD5E1;margin-top:2px;">{sub}</div></div>'
        )

    def _arrow():
        return '<div style="color:#64748B;font-size:16pt;display:flex;align-items:center;padding:0 6px;">→</div>'

    boxes_top = [
        _box("Users", f"{len(users)} identified", "#0891B2", "#22D3EE"),
        _arrow(),
        _box(_sl(name, 18), "Mobile App", "#1D4ED8", "#3B82F6"),
        _arrow(),
        _box("API Endpoints", f"{https_n} HTTPS / {http_n} HTTP", "#14532D" if http_n==0 else "#7C2D12", "#22C55E" if http_n==0 else "#EF4444"),
    ]

    boxes_mid = [
        _box("Auth", f"{_sl(at,12)} · {mfa}", "#7C3AED", "#A78BFA"),
        _box("Storage", f"{_sl(str(db),12)} · Bk:{bk_t}", "#1E3A5F", "#3B82F6"),
    ]
    if dp:
        boxes_mid.append(_box("Sensitive Perms", f"{len(dp)} dangerous", "#7C2D12", "#EF4444"))
    if sens:
        boxes_mid.append(_box("Sensitive Data", f"{len(sens)} items", "#4C1D95", "#A855F7"))
    if exported:
        boxes_mid.append(_box("Exported Comps", f"{len(exported)} found", "#78350F", "#F59E0B"))

    boxes_bot = [
        _box("Attacker", "External Threat", "#991B1B", "#EF4444"),
    ]

    html = '<div style="background:#080D16;border:1px solid #1E293B;border-radius:12px;padding:20px;page-break-inside:avoid;">'
    # Row 1
    html += '<div style="display:flex;justify-content:center;align-items:center;gap:4px;margin-bottom:16px;">'
    html += "".join(boxes_top)
    html += '</div>'
    # Row 2
    html += '<div style="display:flex;justify-content:center;flex-wrap:wrap;gap:10px;margin-bottom:16px;">'
    html += "".join(boxes_mid)
    html += '</div>'
    # Row 3
    html += '<div style="display:flex;justify-content:center;align-items:center;gap:8px;">'
    html += "".join(boxes_bot)
    html += '<div style="color:#EF4444;font-size:8pt;font-style:italic;margin-left:8px;">→ targets app, endpoints, exported components</div>'
    html += '</div>'
    html += '</div>'
    return html
