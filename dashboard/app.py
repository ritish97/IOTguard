"""
IoTGuard Interactive Web Dashboard
Based on: 'A Lightweight Ensemble Learning Approach for Stage-Aware Detection
and Containment of Unseen IoT Attacks at the Network Edge'
"""

import sys
import os
import json
import time
from pathlib import Path
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# Setup path (works from repository root or dashboard/ subfolder)
BASE_DIR = Path(__file__).resolve().parent
if BASE_DIR.name == "dashboard":
    BASE_DIR = BASE_DIR.parent
sys.path.insert(0, str(BASE_DIR))

from config.settings import (
    DEFAULT_THETA,
    DEFAULT_K,
    STAGE_CLASSES,
    STAGE_DESCRIPTIONS,
    FEATURE_COLUMNS,
    MODELS_DIR,
    SAMPLES_DATA_DIR,
    LOGS_DIR
)
from iotguard.models import IoTGuardModel
from iotguard.replay import CaptureReplaySimulator
from iotguard.features import FeatureExtractor
from iotguard.policy import GradedContainmentPolicy
from iotguard.audit import IoT23LabelAuditor

st.set_page_config(
    page_title="IoTGuard: Stage-Aware IoT Intrusion Detection & Containment",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for Humanised Aesthetic theme
st.markdown("""
<style>
    /* Import soft, human-centric font and Material Symbols for crisp UI icons */
    @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700&display=swap');
    @import url('https://fonts.googleapis.com/css2?family=Material+Symbols+Rounded:opsz,wght,FILL,GRAD@20..48,100..700,0..1,-50..200');
    
    /* Apply typography to text elements without overriding system/glyph icons */
    html, body, .stApp {
        font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    }
    
    h1, h2, h3, h4, h5, h6, p, label, .stMarkdown, .stSelectbox, .stSlider {
        font-family: 'Plus Jakarta Sans', sans-serif;
    }

    /* PRESERVE STREAMLIT ICONS & MATERIAL SYMBOLS:
       Explicitly protect icon fonts and glyphs so ligatures (e.g. keyboard_double_arrow_left,
       arrow_upward, bar_chart) render as crisp graphical icons instead of overlapping text strings. */
    .material-symbols-rounded,
    .material-symbols-outlined,
    .material-icons,
    [class*="material-symbols"],
    [class*="material-icons"],
    [data-testid*="stIcon"],
    [data-testid="stIconMaterial"],
    [data-testid="stSidebarCollapseButton"] *,
    [data-testid="stSidebarCollapseButton"] span,
    button[kind="header"] *,
    div[class*="glideDataGrid"] [class*="material"],
    div[class*="dvn-scroller"] *,
    div[class*="header-menu"] *,
    [data-testid="stDataFrame"] span[class*="material"] {
        font-family: 'Material Symbols Rounded', 'Material Icons', sans-serif !important;
        font-feature-settings: 'liga' 1;
        letter-spacing: normal !important;
        text-transform: none !important;
        white-space: nowrap !important;
        word-wrap: normal !important;
        direction: ltr !important;
    }
    
    /* Soften the main container background */
    .stApp {
        background: linear-gradient(180deg, #F9FBFC 0%, #F3F6F9 100%);
    }
    
    /* Clean modern white cards with soft shadows */
    .metric-card {
        background-color: white;
        padding: 20px 24px;
        border-radius: 16px;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05), 0 2px 4px -1px rgba(0, 0, 0, 0.03);
        margin-bottom: 16px;
        border: 1px solid #EAEFF5;
        border-left: 4px solid #4F46E5;
    }
    
    /* Modern tactile buttons with hover lift & glow */
    div.stButton > button:first-child {
        background: linear-gradient(135deg, #6366F1 0%, #4F46E5 100%);
        color: white;
        border: none;
        padding: 10px 24px;
        border-radius: 12px;
        font-weight: 500;
        letter-spacing: -0.2px;
        transition: all 0.2s ease-in-out;
        box-shadow: 0 4px 10px rgba(79, 70, 229, 0.15);
    }
    
    div.stButton > button:first-child:hover {
        transform: translateY(-1px);
        box-shadow: 0 6px 20px rgba(79, 70, 229, 0.25);
        background: linear-gradient(135deg, #4F46E5 0%, #4338CA 100%);
    }
    
    /* Soften text and number inputs */
    .stTextInput div div div input, .stNumberInput div div div input {
        border-radius: 12px;
        border: 1px solid #E2E8F0;
        padding: 10px 14px;
    }

    .stAlert {
        border-radius: 12px;
    }
    
    /* Header card */
    .header-box {
        background: white;
        padding: 26px 30px;
        border-radius: 16px;
        border: 1px solid #EAEFF5;
        box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.04), 0 4px 6px -2px rgba(0, 0, 0, 0.02);
        margin-bottom: 24px;
    }
</style>
""", unsafe_allow_html=True)


@st.cache_resource
def load_model():
    model_path = MODELS_DIR / "iotguard_xgboost.json"
    if not model_path.exists():
        st.error(f"Trained model not found at {model_path}. Please run `python scripts/train.py` first.")
        st.stop()
    model = IoTGuardModel()
    model.load(model_path)
    return model


@st.cache_data
def load_eval_summary():
    path = MODELS_DIR / "evaluation_summary.json"
    if path.exists():
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return None


@st.cache_data
def load_sample_file(path_str):
    p = Path(path_str)
    if p.exists():
        return pd.read_json(p, orient="records", lines=True)
    return None


# Load resources
model = load_model()
eval_summary = load_eval_summary()

# Header banner
st.markdown("""
<div class="header-box">
    <div style="display:flex; align-items:center; gap: 12px; margin-bottom: 8px;">
        <span style="font-size: 2rem;">🛡️</span>
        <h1 style="margin:0; font-size: 2rem; color: #1E293B; font-weight: 700; letter-spacing: -0.5px;">
            IoTGuard: Edge Intrusion Detection & Graded Containment
        </h1>
    </div>
    <p style="margin: 0 0 12px 0; font-size: 1.02rem; color: #64748B; line-height: 1.5;">
        A Lightweight Ensemble Learning Approach for Stage-Aware Detection and Containment of Unseen IoT Attacks at the Network Edge
    </p>
    <div style="display:flex; gap: 10px; flex-wrap: wrap;">
        <span style="background: #EEF2FF; color: #4F46E5; padding: 4px 12px; border-radius: 20px; font-size: 0.85rem; font-weight: 600;">Tier 1 Edge Gateway</span>
        <span style="background: #F0FDF4; color: #16A34A; padding: 4px 12px; border-radius: 20px; font-size: 0.85rem; font-weight: 600;">Stage-Aware XGBoost</span>
        <span style="background: #FFF1F2; color: #E11D48; padding: 4px 12px; border-radius: 20px; font-size: 0.85rem; font-weight: 600;">Automated nftables</span>
    </div>
</div>
""", unsafe_allow_html=True)

# Sidebar settings
st.sidebar.image("https://img.icons8.com/fluency/96/shield.png", width=70)
st.sidebar.title("Gateway Settings")
st.sidebar.markdown("Configure Tier 1 Gateway Policy parameters:")

theta_input = st.sidebar.slider(
    "Confidence Threshold (θ)",
    min_value=0.50,
    max_value=0.99,
    value=float(DEFAULT_THETA),
    step=0.05,
    help="Predicted stage probability must meet or exceed θ to trigger containment."
)

k_input = st.sidebar.slider(
    "Quarantine Hits (k)",
    min_value=1,
    max_value=20,
    value=int(DEFAULT_K),
    step=1,
    help="Number of confident scan/attack verdicts in 60s window required to quarantine device."
)

st.sidebar.markdown("---")
st.sidebar.subheader("📄 System Documentation")
doc_pdf_path = BASE_DIR / "IoTGuard_Architecture_and_Engineering_Documentation.pdf"
if doc_pdf_path.exists():
    with open(doc_pdf_path, "rb") as f:
        pdf_bytes = f.read()
    st.sidebar.download_button(
        label="📥 Download Architecture PDF",
        data=pdf_bytes,
        file_name="IoTGuard_Architecture_and_Engineering_Documentation.pdf",
        mime="application/pdf",
        help="Complete technical specification, architecture diagrams, decision log, and roadmap."
    )

st.sidebar.markdown("---")
st.sidebar.subheader("Stage Architecture")
for stage, desc in STAGE_DESCRIPTIONS.items():
    st.sidebar.caption(f"**{stage.upper()}**: {desc}")

# Main Tabs
replay_res = None
tab_replay, tab_firewall, tab_models, tab_audit, tab_inspector = st.tabs([
    "🎯 Attack Replay & Kill-Chain Timeline",
    "🔥 Gateway Firewall (nftables)",
    "📊 Model Performance & Ablation",
    "🔍 IoT-23 Label Audit",
    "⚡ Real-Time Connection Inspector"
])

# -------------------------------------------------------------
# TAB 1: ATTACK REPLAY & KILL-CHAIN TIMELINE
# -------------------------------------------------------------
with tab_replay:
    st.subheader("Kill-Chain Replay & Early Containment Evaluation")
    st.markdown("""
    Replays gateway connection logs against IoTGuard's graded containment policy.
    Observe how early C2 heartbeats trigger **Level 2 Destination Blocks** and scanning bursts trigger **Level 3 Device Quarantine**.
    """)

    scenario_options = {
        "Capture 39-1: IRCBot Scenario": SAMPLES_DATA_DIR / "capture_39_1_ircbot.json",
        "Capture 34-1: Mirai Botnet (Download -> Scan -> DDoS)": SAMPLES_DATA_DIR / "capture_34_1_mirai.json",
        "Benign Smart Home Device (Philips Hue Lamp)": SAMPLES_DATA_DIR / "capture_benign_hue.json"
    }

    col_s1, col_s2 = st.columns([3, 1])
    with col_s1:
        selected_scenario = st.selectbox("Select IoT Scenario:", list(scenario_options.keys()))
    with col_s2:
        run_btn = st.button("🚀 Replay Scenario", type="primary", use_container_width=True)

    sample_path = scenario_options[selected_scenario]
    sample_df = load_sample_file(str(sample_path))

    if sample_df is not None:
        is_infected = "Benign" not in selected_scenario
        simulator = CaptureReplaySimulator(model=model, theta=theta_input, k=k_input)
        replay_res = simulator.replay_stream(sample_df, is_device_infected=is_infected)

        # Metrics Row
        m1, m2, m3, m4 = st.columns(4)
        with m1:
            st.metric("Total Connections", f"{replay_res['total_connections']:,}")
        with m2:
            st.metric("Infected Device Contained", "YES ✅" if replay_res['device_contained'] else "NO ❌")
        with m3:
            lead = replay_res['lead_time_seconds']
            lead_str = f"{lead:.1f}s" if lead < 9000 else "N/A (Pre-empted)"
            st.metric("Early Containment Lead Time", lead_str)
        with m4:
            st.metric("Harmful Traffic Dropped", f"{replay_res['harmful_dropped_pct']:.2f}%")

        st.markdown("---")
        st.subheader("Interactive Kill-Chain Timeline")

        timeline_data = replay_res["timeline"]
        if timeline_data:
            t_df = pd.DataFrame(timeline_data)

            # Cumulative counts for C2 and Scan
            t_df["is_c2"] = (t_df["true_stage"] == "cnc").astype(int)
            t_df["is_scan"] = (t_df["true_stage"] == "scan").astype(int)
            t_df["cum_c2"] = t_df["is_c2"].cumsum()
            t_df["cum_scan"] = t_df["is_scan"].cumsum()

            # Plotly timeline
            fig = go.Figure()

            # Add C2 curve
            if t_df["cum_c2"].max() > 0:
                fig.add_trace(go.Scatter(
                    x=t_df["relative_time_sec"],
                    y=t_df["cum_c2"],
                    mode="lines",
                    name="C2 Connections",
                    line=dict(color="#3b82f6", width=2.5)
                ))

            # Add Scan curve
            if t_df["cum_scan"].max() > 0:
                fig.add_trace(go.Scatter(
                    x=t_df["relative_time_sec"],
                    y=t_df["cum_scan"],
                    mode="lines",
                    name="Scan Connections",
                    line=dict(color="#ef4444", width=2.5)
                ))

            # Identify L2 Block events and L3 Quarantine event
            l2_events = t_df[t_df["action"] == "L2_BLOCK_DESTINATION"]
            l3_events = t_df[t_df["action"] == "L3_QUARANTINE_DEVICE"]

            for _, l2 in l2_events.iterrows():
                fig.add_vline(
                    x=l2["relative_time_sec"],
                    line_dash="dash",
                    line_color="#06b6d4",
                    annotation_text=f"L2 Block ({l2['resp_h']})",
                    annotation_position="top left"
                )

            for _, l3 in l3_events.iterrows():
                fig.add_vline(
                    x=l3["relative_time_sec"],
                    line_dash="solid",
                    line_color="#a855f7",
                    line_width=3,
                    annotation_text=f"L3 Quarantine ({l3['orig_h']})",
                    annotation_position="top right"
                )

            fig.update_layout(
                title=f"Kill-Chain Timeline: {selected_scenario}",
                xaxis_title="Time Since Capture Start (seconds)",
                yaxis_title="Cumulative Connections (Log Scale)",
                yaxis_type="log",
                template="plotly_white",
                height=480,
                legend=dict(yanchor="top", y=0.95, xanchor="left", x=0.05)
            )
            st.plotly_chart(fig, use_container_width=True)

            # Details
            c_det1, c_det2 = st.columns(2)
            with c_det1:
                st.info(f"**Quarantined Devices ({len(replay_res['quarantined_devices'])}):** "
                        f"{replay_res['quarantined_devices'] or 'None'}")
            with c_det2:
                st.warning(f"**Blocked Destination Pairs ({len(replay_res['blocked_destinations'])}):** "
                           f"{replay_res['blocked_destinations'] or 'None'}")


# -------------------------------------------------------------
# TAB 2: GATEWAY FIREWALL (nftables)
# -------------------------------------------------------------
with tab_firewall:
    st.subheader("Tier 1 Gateway Firewall & Active Containment State")
    st.markdown("""
    All responses escalate with evidence. Malicious verdicts write `nftables` rules
    into the dedicated table `inet iotguard`. An operator can inspect or flush all rules with a single command.
    """)

    f_col1, f_col2 = st.columns(2)
    with f_col1:
        st.markdown("### 🚫 Level 3: Quarantined Devices")
        st.markdown("*All forwarded traffic dropped for these devices.*")
        if replay_res is not None and replay_res['quarantined_devices']:
            quar_data = [{"Device IP": dev, "Status": "QUARANTINED", "Action": "DROP ALL"} for dev in replay_res['quarantined_devices']]
            st.dataframe(pd.DataFrame(quar_data), use_container_width=True, hide_index=True)
        else:
            st.success("No devices currently quarantined. Network healthy.")

    with f_col2:
        st.markdown("### 🛑 Level 2: Blocked Destinations")
        st.markdown("*Traffic dropped to specific C2/Payload hosts only; legitimate cloud access unaffected.*")
        if replay_res is not None and replay_res['blocked_destinations']:
            block_data = [{"Rule": b, "Status": "BLOCKED", "Type": "C2 / Download Target"} for b in replay_res['blocked_destinations']]
            st.dataframe(pd.DataFrame(block_data), use_container_width=True, hide_index=True)
        else:
            st.info("No destination blocks active.")

    st.markdown("---")
    st.subheader("Dedicated nftables Ruleset (nftables.conf)")
    policy_gen = GradedContainmentPolicy()
    st.code(policy_gen.generate_nftables_init_script(), language="bash")


# -------------------------------------------------------------
# TAB 3: MODEL PERFORMANCE & ABLATION
# -------------------------------------------------------------
with tab_models:
    st.subheader("Experimental Evaluation: Model Comparison on Temporal Split")
    st.markdown("""
    Consecutive connections in a capture are often near-duplicates, so IoTGuard evaluates on a
    **per-capture temporal split** (70% train, 30% test) to prevent data leakage and evaluate real edge generalization.
    """)

    if eval_summary:
        comp_rows = []
        for model_name, res in eval_summary.items():
            comp_rows.append({
                "Model": model_name,
                "Macro F1": f"{res['macro_f1']:.3f}",
                "Binary F1": f"{res['binary_f1']:.3f}",
                "Benign FPR": f"{res['benign_fpr'] * 100:.2f}%",
                "C2 F1": f"{res['c2_f1']:.3f}"
            })
        st.dataframe(pd.DataFrame(comp_rows), use_container_width=True, hide_index=True)

        st.markdown("---")
        c_m1, c_m2 = st.columns(2)

        with c_m1:
            st.subheader("Confusion Matrix")
            iotguard_res = eval_summary.get("IoTGuard (XGBoost)", {})
            if "confusion_matrix" in iotguard_res:
                cm = np.array(iotguard_res["confusion_matrix"])
                # Normalize row-wise
                cm_norm = cm.astype('float') / np.maximum(cm.sum(axis=1)[:, np.newaxis], 1)

                fig_cm = px.imshow(
                    cm_norm,
                    labels=dict(x="Predicted Stage", y="True Stage", color="Rate"),
                    x=STAGE_CLASSES,
                    y=STAGE_CLASSES,
                    text_auto=".2%",
                    color_continuous_scale="Blues"
                )
                fig_cm.update_layout(template="plotly_white", height=420)
                st.plotly_chart(fig_cm, use_container_width=True)

        with c_m2:
            st.subheader("Feature Importance by Gain")
            feat_df = model.get_feature_importances()
            top_feats = feat_df.head(10).copy()
            top_feats["Category"] = top_feats["is_window"].map({True: "Window Feature (last 60s)", False: "Per-Connection Feature"})

            fig_feat = px.bar(
                top_feats,
                x="share_pct",
                y="feature",
                orientation="h",
                color="Category",
                color_discrete_map={"Window Feature (last 60s)": "#f59e0b", "Per-Connection Feature": "#3b82f6"},
                labels={"share_pct": "Share of Total Gain (%)", "feature": "Feature"},
                title="Top 10 Most Important Features"
            )
            fig_feat.update_layout(yaxis=dict(autorange="reversed"), template="plotly_white", height=420)
            st.plotly_chart(fig_feat, use_container_width=True)


# -------------------------------------------------------------
# TAB 4: IOT-23 LABEL AUDIT
# -------------------------------------------------------------
with tab_audit:
    st.subheader("Label Audit of IoT-23")
    st.markdown(r"""
    In several IoT-23 version 1 captures, **82.4% of benign-labelled connections**
    behave indistinguishably from scanning (contacting $\ge 100$ distinct destinations within 60s with $\ge 90\%$ failed attempts).
    This audit explains cross-capture evaluation errors and prevents models from learning flawed ground truth.
    """)

    audit_data = [
        {"Capture (family)": "35-1 (Mirai)", "Benign Total": "133,398", "Scan-like": "133,100", "Share (%)": "99.8%"},
        {"Capture (family)": "33-1 (Kenjiro)", "Benign Total": "2,948", "Scan-like": "2,896", "Share (%)": "98.2%"},
        {"Capture (family)": "1-1 (Hide&Seek)", "Benign Total": "51,276", "Scan-like": "37,749", "Share (%)": "73.6%"},
        {"Capture (family)": "49-1 (Mirai)", "Benign Total": "76", "Scan-like": "43", "Share (%)": "56.6%"},
        {"Capture (family)": "9-1 (Hajime)", "Benign Total": "1,119", "Scan-like": "431", "Share (%)": "38.5%"},
        {"Capture (family)": "Other 16 captures", "Benign Total": "22,582", "Scan-like": "28", "Share (%)": "0.1%"},
        {"Capture (family)": "ALL 21 CAPTURES", "Benign Total": "211,399", "Scan-like": "174,247", "Share (%)": "82.4%"}
    ]
    st.table(pd.DataFrame(audit_data))

    st.info("""
    **Key Takeaway:** Excluding these mislabelled scan-like flows reduces the leave-one-capture-out
    benign false-positive rate from 69.0% to 16.7%.
    """)


# -------------------------------------------------------------
# TAB 5: REAL-TIME CONNECTION INSPECTOR
# -------------------------------------------------------------
with tab_inspector:
    st.subheader("Interactive Single Connection Inspector")
    st.markdown("Test the IoTGuard classifier and policy engine with custom flow attributes.")

    with st.form("custom_flow_form"):
        col1, col2, col3 = st.columns(3)
        with col1:
            in_orig_h = st.text_input("Origin Device IP", "192.168.1.195")
            in_resp_h = st.text_input("Destination IP", "185.244.25.187")
            in_resp_p = st.number_input("Destination Port", value=6667)
            in_proto = st.selectbox("Protocol", ["tcp", "udp", "icmp"])
        with col2:
            in_conn_state = st.selectbox("Zeek Conn State", ["SF", "S0", "REJ", "RSTO", "OTH"])
            in_duration = st.number_input("Duration (seconds)", value=1.5, step=0.1)
            in_orig_bytes = st.number_input("Originator Bytes", value=250)
            in_resp_bytes = st.number_input("Responder Bytes", value=450)
        with col3:
            in_orig_pkts = st.number_input("Originator Packets", value=4)
            in_resp_pkts = st.number_input("Responder Packets", value=3)
            in_history = st.text_input("TCP History", "ShADadFf")
            in_ts = st.number_input("Timestamp", value=1540000100.0)

        submit_test = st.form_submit_button("⚡ Classify Connection")

    if submit_test:
        sample_rec = {
            "ts": in_ts,
            "id.orig_h": in_orig_h,
            "id.resp_h": in_resp_h,
            "id.resp_p": in_resp_p,
            "proto": in_proto,
            "conn_state": in_conn_state,
            "duration": in_duration,
            "orig_bytes": in_orig_bytes,
            "resp_bytes": in_resp_bytes,
            "orig_pkts": in_orig_pkts,
            "resp_pkts": in_resp_pkts,
            "orig_ip_bytes": in_orig_bytes + (in_orig_pkts * 40),
            "resp_ip_bytes": in_resp_bytes + (in_resp_pkts * 40),
            "missed_bytes": 0,
            "history": in_history
        }

        fe = FeatureExtractor()
        ext = fe.extract_from_record(sample_rec)
        features = ext["features"]
        meta = ext["metadata"]

        stage, conf, probs = model.predict_single(features)
        policy_engine = GradedContainmentPolicy(theta=theta_input, k=k_input)
        verdict = policy_engine.evaluate_verdict(stage, conf, meta)

        st.markdown("### Inference Result")
        res_col1, res_col2 = st.columns(2)
        with res_col1:
            st.success(f"**Predicted Stage:** {stage.upper()}")
            st.metric("Confidence (p)", f"{conf:.4f}")
            st.metric("Action Triggered", verdict["action"])
            st.caption(f"**Action Level:** {verdict['action_level']} | **Reason:** {verdict['reason']}")

        with res_col2:
            st.markdown("**Stage Probability Distribution:**")
            prob_df = pd.DataFrame([{"Stage": k, "Probability": v} for k, v in probs.items()])
            fig_prob = px.bar(prob_df, x="Stage", y="Probability", color="Stage", template="plotly_white")
            st.plotly_chart(fig_prob, use_container_width=True)
