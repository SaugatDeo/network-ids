import streamlit as st
import requests
import pandas as pd
import numpy as np
import time
import random
from datetime import datetime, timedelta
import plotly.graph_objects as go
import plotly.express as px

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="NetGuard AI — SOC Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ── Custom CSS ─────────────────────────────────────────────────────────────────
st.markdown("""
<style>
    /* Dark SOC theme */
    .stApp { background-color: #0a0e1a; }
    .main { background-color: #0a0e1a; }
    
    /* Header */
    .header-bar {
        background: linear-gradient(90deg, #0d1b2a 0%, #1a2a4a 50%, #0d1b2a 100%);
        border-bottom: 1px solid #00ff88;
        padding: 1rem 2rem;
        border-radius: 8px;
        margin-bottom: 1.5rem;
    }
    .header-title {
        color: #00ff88;
        font-size: 1.8rem;
        font-weight: 700;
        letter-spacing: 2px;
        font-family: monospace;
    }
    .header-sub {
        color: #8892a4;
        font-size: 0.8rem;
        letter-spacing: 1px;
        font-family: monospace;
    }

    /* Metric cards */
    .metric-card {
        background: #0d1b2a;
        border: 1px solid #1e3a5f;
        border-radius: 8px;
        padding: 1rem 1.25rem;
        margin-bottom: 0.75rem;
    }
    .metric-label {
        font-size: 0.7rem;
        color: #8892a4;
        text-transform: uppercase;
        letter-spacing: 0.1em;
        font-family: monospace;
    }
    .metric-value {
        font-size: 1.8rem;
        font-weight: 700;
        font-family: monospace;
    }
    .metric-green { color: #00ff88; }
    .metric-red { color: #ff4444; }
    .metric-yellow { color: #ffaa00; }
    .metric-blue { color: #00aaff; }

    /* Alert rows */
    .alert-critical {
        background: rgba(255, 0, 0, 0.1);
        border-left: 3px solid #ff0000;
        padding: 0.6rem 1rem;
        margin-bottom: 0.4rem;
        border-radius: 4px;
        font-family: monospace;
        font-size: 0.8rem;
        color: #ff6666;
    }
    .alert-high {
        background: rgba(255, 100, 0, 0.1);
        border-left: 3px solid #ff6400;
        padding: 0.6rem 1rem;
        margin-bottom: 0.4rem;
        border-radius: 4px;
        font-family: monospace;
        font-size: 0.8rem;
        color: #ffaa44;
    }
    .alert-normal {
        background: rgba(0, 255, 136, 0.05);
        border-left: 3px solid #00ff88;
        padding: 0.6rem 1rem;
        margin-bottom: 0.4rem;
        border-radius: 4px;
        font-family: monospace;
        font-size: 0.8rem;
        color: #44ffaa;
    }

    /* Section headers */
    .section-header {
        font-size: 0.75rem;
        color: #00ff88;
        text-transform: uppercase;
        letter-spacing: 0.15em;
        font-family: monospace;
        border-bottom: 1px solid #1e3a5f;
        padding-bottom: 0.5rem;
        margin-bottom: 1rem;
    }

    /* SHAP bar */
    .shap-row {
        display: flex;
        align-items: center;
        gap: 8px;
        margin-bottom: 6px;
        font-family: monospace;
        font-size: 0.75rem;
    }
    .shap-label { color: #8892a4; width: 160px; flex-shrink: 0; }
    .shap-bar-pos { background: #ff4444; height: 6px; border-radius: 3px; }
    .shap-bar-neg { background: #00ff88; height: 6px; border-radius: 3px; }
    .shap-val-pos { color: #ff4444; width: 50px; text-align: right; }
    .shap-val-neg { color: #00ff88; width: 50px; text-align: right; }

    /* Sidebar */
    section[data-testid="stSidebar"] {
        background-color: #0d1b2a;
        border-right: 1px solid #1e3a5f;
    }

    /* Hide streamlit default */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    .stDeployButton {display: none;}
</style>
""", unsafe_allow_html=True)

# ── Traffic simulator ──────────────────────────────────────────────────────────
PROTOCOLS = ["tcp", "udp", "icmp", "arp"]
SERVICES = ["http", "ftp", "smtp", "ssh", "dns", "ftp-data", "-", "pop3"]
STATES = ["FIN", "INT", "CON", "REQ", "RST"]
ATTACK_PROFILES = {
    "normal": {"sttl": (60, 128), "sbytes": (100, 2000), "ct_dst_src_ltm": (1, 5)},
    "dos": {"sttl": (1, 30), "sbytes": (5000, 50000), "ct_dst_src_ltm": (50, 200)},
    "port_scan": {"sttl": (40, 60), "sbytes": (40, 100), "ct_dst_src_ltm": (20, 100)},
    "exploit": {"sttl": (55, 65), "sbytes": (1000, 8000), "ct_dst_src_ltm": (10, 50)},
}

def random_ip():
    return f"{random.randint(1,254)}.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(1,254)}"

def simulate_traffic(profile="random"):
    if profile == "random":
        profile = random.choices(
            ["normal", "dos", "port_scan", "exploit"],
            weights=[0.5, 0.2, 0.15, 0.15]
        )[0]

    p = ATTACK_PROFILES[profile]
    sttl = random.randint(*p["sttl"])
    sbytes = random.randint(*p["sbytes"])
    ct_dst = random.randint(*p["ct_dst_src_ltm"])

    return {
        "dur": round(random.uniform(0, 10), 4),
        "proto": random.choice(PROTOCOLS),
        "service": random.choice(SERVICES),
        "state": random.choice(STATES),
        "spkts": random.randint(1, 500),
        "dpkts": random.randint(1, 500),
        "sbytes": sbytes,
        "dbytes": random.randint(0, sbytes),
        "rate": round(random.uniform(0, 1000), 2),
        "sttl": sttl,
        "dttl": random.randint(0, 128),
        "sload": round(random.uniform(0, 100000), 2),
        "dload": round(random.uniform(0, 100000), 2),
        "sloss": random.randint(0, 10),
        "dloss": random.randint(0, 10),
        "sinpkt": round(random.uniform(0, 1000), 4),
        "dinpkt": round(random.uniform(0, 1000), 4),
        "sjit": round(random.uniform(0, 100), 4),
        "djit": round(random.uniform(0, 100), 4),
        "swin": random.randint(0, 65535),
        "stcpb": random.randint(0, 1000000),
        "dtcpb": random.randint(0, 1000000),
        "dwin": random.randint(0, 65535),
        "tcprtt": round(random.uniform(0, 1), 4),
        "synack": round(random.uniform(0, 1), 4),
        "ackdat": round(random.uniform(0, 1), 4),
        "smean": random.randint(0, 1500),
        "dmean": random.randint(0, 1500),
        "trans_depth": random.randint(0, 10),
        "response_body_len": random.randint(0, 10000),
        "ct_srv_src": random.randint(1, 50),
        "ct_state_ttl": random.randint(0, 6),
        "ct_dst_ltm": random.randint(1, 50),
        "ct_src_dport_ltm": random.randint(1, 50),
        "ct_dst_sport_ltm": random.randint(1, 50),
        "ct_dst_src_ltm": ct_dst,
        "is_ftp_login": random.randint(0, 1),
        "ct_ftp_cmd": random.randint(0, 5),
        "ct_flw_http_mthd": random.randint(0, 5),
        "ct_src_ltm": random.randint(1, 50),
        "ct_srv_dst": random.randint(1, 50),
        "is_sm_ips_ports": random.randint(0, 1),
    }

# ── Session state ──────────────────────────────────────────────────────────────
if "alerts" not in st.session_state:
    st.session_state.alerts = []
if "total_scanned" not in st.session_state:
    st.session_state.total_scanned = 0
if "total_attacks" not in st.session_state:
    st.session_state.total_attacks = 0
if "running" not in st.session_state:
    st.session_state.running = False

# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown('<div class="section-header">⚙ SYSTEM CONFIG</div>', unsafe_allow_html=True)

    api_url = st.text_input(
        "API Endpoint",
        value="https://saugatiwi-network-ids.hf.space",
        help="FastAPI backend URL"
    )

    st.markdown("---")
    st.markdown('<div class="section-header">🎛 SIMULATION</div>', unsafe_allow_html=True)

    sim_speed = st.slider("Scan interval (seconds)", 0.5, 5.0, 1.5, 0.5)
    max_alerts = st.slider("Max alerts to display", 10, 100, 30)

    col1, col2 = st.columns(2)
    with col1:
        if st.button("▶ START", use_container_width=True):
            st.session_state.running = True
    with col2:
        if st.button("⏹ STOP", use_container_width=True):
            st.session_state.running = False

    if st.button("🗑 Clear Alerts", use_container_width=True):
        st.session_state.alerts = []
        st.session_state.total_scanned = 0
        st.session_state.total_attacks = 0

    st.markdown("---")
    st.markdown('<div class="section-header">📊 MODEL INFO</div>', unsafe_allow_html=True)

    try:
        info = requests.get(f"{api_url}/health", timeout=2).json()
        st.markdown(f"""
        <div style="font-family:monospace;font-size:0.75rem;color:#8892a4;">
        MODEL: <span style="color:#00ff88">{info['model']}</span><br>
        DATASET: <span style="color:#00ff88">{info['dataset']}</span><br>
        AUC-ROC: <span style="color:#00ff88">{info['auc_roc']}</span><br>
        ACCURACY: <span style="color:#00ff88">{info['accuracy']*100:.0f}%</span>
        </div>
        """, unsafe_allow_html=True)
    except:
        st.markdown('<span style="color:#ff4444;font-family:monospace;font-size:0.75rem;">⚠ API OFFLINE</span>', unsafe_allow_html=True)

    st.markdown("---")
    st.markdown('<div class="section-header">🔍 MANUAL SCAN</div>', unsafe_allow_html=True)
    manual_scan = st.button("Scan Custom Traffic", use_container_width=True)

# ── Header ─────────────────────────────────────────────────────────────────────
st.markdown(f"""
<div class="header-bar">
    <div class="header-title">🛡️ NETGUARD AI — SOC DASHBOARD</div>
    <div class="header-sub">
        AI-POWERED NETWORK INTRUSION DETECTION · UNSW-NB15 · XGBoost + SHAP · AUC-ROC: 0.9856
        &nbsp;&nbsp;|&nbsp;&nbsp;
        STATUS: <span style="color:#{'00ff88' if st.session_state.running else 'ff4444'}">
        {'● MONITORING' if st.session_state.running else '○ STANDBY'}</span>
        &nbsp;&nbsp;|&nbsp;&nbsp;
        {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    </div>
</div>
""", unsafe_allow_html=True)

# ── Top metrics ────────────────────────────────────────────────────────────────
m1, m2, m3, m4 = st.columns(4)

attack_rate = (st.session_state.total_attacks / st.session_state.total_scanned * 100) if st.session_state.total_scanned > 0 else 0

with m1:
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-label">Total Scanned</div>
        <div class="metric-value metric-blue">{st.session_state.total_scanned:,}</div>
    </div>
    """, unsafe_allow_html=True)

with m2:
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-label">Attacks Detected</div>
        <div class="metric-value metric-red">{st.session_state.total_attacks:,}</div>
    </div>
    """, unsafe_allow_html=True)

with m3:
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-label">Attack Rate</div>
        <div class="metric-value {'metric-red' if attack_rate > 30 else 'metric-yellow' if attack_rate > 10 else 'metric-green'}">{attack_rate:.1f}%</div>
    </div>
    """, unsafe_allow_html=True)

with m4:
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-label">Normal Traffic</div>
        <div class="metric-value metric-green">{st.session_state.total_scanned - st.session_state.total_attacks:,}</div>
    </div>
    """, unsafe_allow_html=True)

# ── Main layout ────────────────────────────────────────────────────────────────
col_left, col_right = st.columns([2, 1])

with col_left:
    st.markdown('<div class="section-header">⚡ LIVE ALERT FEED</div>', unsafe_allow_html=True)
    alert_container = st.empty()

    # ── Charts ─────────────────────────────────────────────────────────────────
    if st.session_state.alerts:
        df_alerts = pd.DataFrame(st.session_state.alerts)

        chart_col1, chart_col2 = st.columns(2)

        with chart_col1:
            st.markdown('<div class="section-header">📈 ATTACK TIMELINE</div>', unsafe_allow_html=True)
            timeline_data = df_alerts.copy()
            timeline_data['is_attack'] = timeline_data['prediction'] == 'Attack'
            timeline_data['index'] = range(len(timeline_data))

            fig = go.Figure()
            fig.add_trace(go.Scatter(
                x=timeline_data['index'],
                y=timeline_data['attack_probability'],
                mode='lines+markers',
                line=dict(color='#00ff88', width=1.5),
                marker=dict(
                    color=['#ff4444' if p == 'Attack' else '#00ff88'
                           for p in timeline_data['prediction']],
                    size=6
                ),
                name='Attack Probability'
            ))
            fig.add_hline(y=50, line_dash="dash", line_color="#ffaa00",
                         annotation_text="Threshold")
            fig.update_layout(
                paper_bgcolor='#0d1b2a',
                plot_bgcolor='#0a0e1a',
                font=dict(color='#8892a4', family='monospace', size=10),
                margin=dict(l=10, r=10, t=10, b=10),
                height=200,
                showlegend=False,
                xaxis=dict(showgrid=False, color='#1e3a5f'),
                yaxis=dict(showgrid=True, gridcolor='#1e3a5f',
                          range=[0, 100], ticksuffix='%')
            )
            st.plotly_chart(fig, use_container_width=True)

        with chart_col2:
            st.markdown('<div class="section-header">🥧 TRAFFIC BREAKDOWN</div>', unsafe_allow_html=True)
            counts = df_alerts['prediction'].value_counts()
            fig2 = go.Figure(go.Pie(
                labels=counts.index,
                values=counts.values,
                hole=0.6,
                marker=dict(colors=['#ff4444', '#00ff88']),
                textfont=dict(family='monospace', size=11)
            ))
            fig2.update_layout(
                paper_bgcolor='#0d1b2a',
                font=dict(color='#8892a4', family='monospace', size=10),
                margin=dict(l=10, r=10, t=10, b=10),
                height=200,
                showlegend=True,
                legend=dict(font=dict(color='#8892a4'))
            )
            st.plotly_chart(fig2, use_container_width=True)

with col_right:
    st.markdown('<div class="section-header">🔬 SHAP EXPLANATION</div>', unsafe_allow_html=True)
    shap_container = st.empty()

    st.markdown('<div class="section-header">🌐 LATEST CONNECTION</div>', unsafe_allow_html=True)
    conn_container = st.empty()

# ── Manual scan section ────────────────────────────────────────────────────────
if manual_scan:
    st.markdown("---")
    st.markdown('<div class="section-header">🔍 MANUAL TRAFFIC ANALYSIS</div>', unsafe_allow_html=True)

    mc1, mc2, mc3 = st.columns(3)
    with mc1:
        m_proto = st.selectbox("Protocol", ["tcp", "udp", "icmp", "arp"])
        m_service = st.selectbox("Service", ["http", "ftp", "smtp", "ssh", "dns", "-"])
        m_state = st.selectbox("State", ["FIN", "INT", "CON", "REQ", "RST"])
    with mc2:
        m_sttl = st.number_input("Source TTL", 0, 255, 64)
        m_sbytes = st.number_input("Source Bytes", 0, 100000, 500)
        m_dbytes = st.number_input("Dest Bytes", 0, 100000, 300)
    with mc3:
        m_ct_dst = st.number_input("ct_dst_src_ltm", 0, 500, 5)
        m_spkts = st.number_input("Source Packets", 0, 10000, 10)
        m_dpkts = st.number_input("Dest Packets", 0, 10000, 8)

    if st.button("🔎 Analyze This Traffic", use_container_width=True):
        manual_traffic = simulate_traffic()
        manual_traffic.update({
            "proto": m_proto,
            "service": m_service,
            "state": m_state,
            "sttl": m_sttl,
            "sbytes": m_sbytes,
            "dbytes": m_dbytes,
            "ct_dst_src_ltm": m_ct_dst,
            "spkts": m_spkts,
            "dpkts": m_dpkts,
        })
        try:
            resp = requests.post(f"{api_url}/predict", json=manual_traffic, timeout=10)
            result = resp.json()

            color = "#ff4444" if result['prediction'] == 'Attack' else "#00ff88"
            st.markdown(f"""
            <div style="background:#0d1b2a;border:1px solid {color};border-radius:8px;
                        padding:1.5rem;font-family:monospace;">
                <div style="font-size:1.5rem;color:{color};font-weight:700;">
                    {result['prediction']} — {result['attack_probability']}% confidence
                </div>
                <div style="color:#8892a4;margin-top:0.5rem;font-size:0.8rem;">
                    Top reasons:
                </div>
            """, unsafe_allow_html=True)

            for reason in result['top_reasons']:
                direction_color = "#ff4444" if reason['impact'] > 0 else "#00ff88"
                st.markdown(f"""
                <div style="font-family:monospace;font-size:0.8rem;color:{direction_color};
                            margin-left:1rem;">
                    → {reason['feature']}: {reason['impact']:+.4f} ({reason['direction']})
                </div>
                """, unsafe_allow_html=True)

            st.markdown("</div>", unsafe_allow_html=True)
        except Exception as e:
            st.error(f"Error: {e}")

# ── Simulation loop ────────────────────────────────────────────────────────────
if st.session_state.running:
    traffic = simulate_traffic()
    src_ip = random_ip()
    dst_ip = random_ip()

    try:
        resp = requests.post(f"{api_url}/predict", json=traffic, timeout=5)
        result = resp.json()

        alert = {
            "time": datetime.now().strftime("%H:%M:%S"),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "proto": traffic['proto'].upper(),
            "service": traffic['service'],
            "prediction": result['prediction'],
            "attack_probability": result['attack_probability'],
            "top_reasons": result['top_reasons'],
            "traffic": traffic
        }

        st.session_state.alerts.insert(0, alert)
        st.session_state.alerts = st.session_state.alerts[:max_alerts]
        st.session_state.total_scanned += 1
        if result['prediction'] == 'Attack':
            st.session_state.total_attacks += 1

        # Render alerts
        alerts_html = ""
        for a in st.session_state.alerts[:15]:
            css = "alert-critical" if a['attack_probability'] > 80 else \
                  "alert-high" if a['prediction'] == 'Attack' else "alert-normal"
            icon = "🔴" if a['attack_probability'] > 80 else \
                   "🟠" if a['prediction'] == 'Attack' else "🟢"
            alerts_html += f"""
            <div class="{css}">
                {icon} [{a['time']}] {a['src_ip']} → {a['dst_ip']}
                &nbsp;|&nbsp; {a['proto']}/{a['service']}
                &nbsp;|&nbsp; <strong>{a['prediction']}</strong>
                &nbsp;|&nbsp; {a['attack_probability']}%
            </div>
            """
        alert_container.markdown(alerts_html, unsafe_allow_html=True)

        # SHAP panel
        shap_html = ""
        max_impact = max(abs(r['impact']) for r in result['top_reasons']) or 1
        for reason in result['top_reasons']:
            bar_width = int(abs(reason['impact']) / max_impact * 100)
            bar_class = "shap-bar-pos" if reason['impact'] > 0 else "shap-bar-neg"
            val_class = "shap-val-pos" if reason['impact'] > 0 else "shap-val-neg"
            shap_html += f"""
            <div class="shap-row">
                <div class="shap-label">{reason['feature']}</div>
                <div style="flex:1;background:#1e3a5f;border-radius:3px;height:6px;">
                    <div class="{bar_class}" style="width:{bar_width}%;"></div>
                </div>
                <div class="{val_class}">{reason['impact']:+.3f}</div>
            </div>
            """
        shap_container.markdown(shap_html, unsafe_allow_html=True)

        # Connection info
        conn_container.markdown(f"""
        <div style="font-family:monospace;font-size:0.75rem;color:#8892a4;
                    background:#0d1b2a;border:1px solid #1e3a5f;
                    border-radius:6px;padding:0.75rem;">
            SRC: <span style="color:#00aaff">{src_ip}</span><br>
            DST: <span style="color:#00aaff">{dst_ip}</span><br>
            PROTO: <span style="color:#ffaa00">{traffic['proto'].upper()}</span>
            &nbsp; SERVICE: <span style="color:#ffaa00">{traffic['service']}</span><br>
            BYTES: <span style="color:#ffffff">{traffic['sbytes']:,}</span>
            &nbsp; TTL: <span style="color:#ffffff">{traffic['sttl']}</span><br>
            CONN_COUNT: <span style="color:#ffffff">{traffic['ct_dst_src_ltm']}</span>
        </div>
        """, unsafe_allow_html=True)

    except Exception as e:
        st.error(f"API Error: {e}")

    time.sleep(sim_speed)
    st.rerun()
