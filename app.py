import time
import sqlite3
import hashlib
import json
from datetime import datetime, timedelta
import random
import io
import pandas as pd
import plotly.graph_objects as go
import streamlit as st
from streamlit_autorefresh import st_autorefresh
from docx import Document
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors

# Page Configuration
st.set_page_config(
    page_title="CloudGuard | Autonomous FinOps Control Plane",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS & Styling (Strictly English)
st.markdown(
    """
<style>
@import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

html, body, [class*="css"] {
    font-family: 'Plus Jakarta Sans', system-ui, sans-serif;
}

/* Keep the browser root dark while Streamlit applies an incremental live update.
   This prevents the brief dark/light flash without stopping the data stream. */
html, body, #root, [data-testid="stAppViewContainer"] {
    background-color: #090d16 !important;
}

.stApp {
    background:
        radial-gradient(1000px 500px at 50% -10%, rgba(56, 189, 248, 0.08), transparent 60%),
        #090d16;
    color: #e2e8f0;
}

header[data-testid="stHeader"] { background: transparent; }
#MainMenu, footer { visibility: hidden; }

.hero {
    border: 1px solid rgba(148, 163, 184, 0.15);
    background: linear-gradient(180deg, rgba(15, 23, 42, 0.9), rgba(11, 18, 32, 0.7));
    padding: 16px 22px 14px;
    margin-bottom: 14px;
    border-radius: 14px;
}
.hero-kicker {
    color: #38bdf8;
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
    letter-spacing: 0.18em;
    text-transform: uppercase;
}
.hero h1 {
    margin: 6px 0 4px;
    font-size: 24px;
    color: #f8fafc;
    font-weight: 700;
}
.hero p { color: #94a3b8; margin: 0; font-size: 13px; }

div[data-testid="stMetric"] {
    background: #111827;
    border: 1px solid rgba(148, 163, 184, 0.15);
    border-radius: 12px;
    padding: 12px 16px;
}
div[data-testid="stMetric"] label { color: #94a3b8 !important; }
div[data-testid="stMetric"] [data-testid="stMetricValue"] { color: #f8fafc !important; font-weight: 700; }

.panel {
    border: 1px solid rgba(148, 163, 184, 0.15);
    background: rgba(17, 24, 39, 0.75);
    border-radius: 14px;
    padding: 14px 18px;
    margin-bottom: 14px;
}

.alert-box {
    border: 1px solid rgba(239, 68, 68, 0.4);
    background: linear-gradient(180deg, rgba(69, 10, 10, 0.7), rgba(17, 24, 39, 0.8));
    border-radius: 12px;
    padding: 14px 16px;
    margin-bottom: 10px;
}
.alert-title { color: #f87171; font-weight: 700; font-size: 14px; }
.alert-sub { color: #fecaca; font-size: 12px; margin: 4px 0 8px; }

.ok-box {
    border: 1px solid rgba(52, 211, 153, 0.4);
    background: rgba(6, 78, 59, 0.3);
    border-radius: 12px;
    padding: 14px 16px;
    color: #d1fae5;
    font-size: 13px;
}

.terminal-box {
    background: #030712;
    border: 1px solid rgba(56, 189, 248, 0.2);
    border-radius: 10px;
    padding: 12px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 11.5px;
    color: #38bdf8;
    height: 480px;
    overflow-y: auto;
}

.stButton > button {
    background: #2563eb;
    color: #fff;
    border: 1px solid #3b82f6;
    font-weight: 600;
    width: 100%;
    height: 42px;
    border-radius: 10px;
    transition: all 0.2s ease;
}
.stButton > button:hover {
    background: #1d4ed8;
    border-color: #60a5fa;
    color: #fff;
}

.user-badge {
    background: linear-gradient(180deg, rgba(15, 23, 42, 0.9), rgba(11, 18, 32, 0.95));
    border: 1px solid rgba(56, 189, 248, 0.25);
    border-radius: 12px;
    padding: 14px;
    margin-bottom: 12px;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
}

.form-label-style {
    font-family: 'JetBrains Mono', monospace;
    font-size: 15px;
    font-weight: 700;
    color: #f8fafc;
    padding-top: 10px;
}
</style>
""",
    unsafe_allow_html=True,
)

# SQLite Database Initialization
def init_db():
    conn = sqlite3.connect("cloudguard_users.db", check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            email TEXT PRIMARY KEY,
            password TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS workspaces (
            email TEXT,
            workspace_name TEXT,
            PRIMARY KEY (email, workspace_name)
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS workspace_state (
            email TEXT,
            workspace_name TEXT,
            stream_records TEXT,
            total_spend REAL,
            audit_logs TEXT,
            selected_apis TEXT,
            PRIMARY KEY (email, workspace_name)
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS credential_vault (
            email TEXT,
            workspace_name TEXT,
            service_name TEXT,
            access_key_id TEXT,
            secret_key_masked TEXT,
            endpoint_url TEXT,
            PRIMARY KEY (email, workspace_name, service_name)
        )
    """)
    try:
        cursor.execute("SELECT selected_apis FROM workspace_state LIMIT 1")
    except sqlite3.OperationalError:
        cursor.execute("ALTER TABLE workspace_state ADD COLUMN selected_apis TEXT")
    conn.commit()
    conn.close()

init_db()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def register_user(email, password):
    conn = sqlite3.connect("cloudguard_users.db", check_same_thread=False)
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO users (email, password, created_at) VALUES (?, ?, ?)",
                       (email, hash_password(password), datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
        conn.commit()
        success = True
    except sqlite3.IntegrityError:
        success = False
    conn.close()
    return success

def verify_user(email, password):
    conn = sqlite3.connect("cloudguard_users.db", check_same_thread=False)
    cursor = conn.cursor()
    # Return the stored email rather than the spelling typed into the form.  This
    # keeps old users linked to their existing workspaces even when they type a
    # different email case on a later login.
    cursor.execute("SELECT email, password FROM users WHERE lower(trim(email)) = lower(trim(?))", (email,))
    row = cursor.fetchone()
    conn.close()
    return row[0] if row and row[1] == hash_password(password) else None

def get_db_workspaces(email):
    conn = sqlite3.connect("cloudguard_users.db", check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute("SELECT workspace_name FROM workspaces WHERE email = ?", (email,))
    rows = cursor.fetchall()
    conn.close()
    return [r[0] for r in rows]

def add_db_workspace(email, ws_name):
    conn = sqlite3.connect("cloudguard_users.db", check_same_thread=False)
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO workspaces (email, workspace_name) VALUES (?, ?)", (email, ws_name))
        conn.commit()
        success = True
    except sqlite3.IntegrityError:
        success = False
    conn.close()
    return success

def save_workspace_state(email, ws_name, records, spend, logs, apis):
    if not email or not ws_name:
        return
    conn = sqlite3.connect("cloudguard_users.db", check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT OR REPLACE INTO workspace_state (email, workspace_name, stream_records, total_spend, audit_logs, selected_apis)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (email, ws_name, json.dumps(records), spend, json.dumps(logs), json.dumps(apis)))
    conn.commit()
    conn.close()

def load_workspace_state(email, ws_name):
    if not email or not ws_name:
        return [], 0.0, ["[SYSTEM_INIT] Secure Credential Vault & Telemetry Engine online."], []
    conn = sqlite3.connect("cloudguard_users.db", check_same_thread=False)
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT stream_records, total_spend, audit_logs, selected_apis FROM workspace_state WHERE email = ? AND workspace_name = ?", (email, ws_name))
        row = cursor.fetchone()
    except sqlite3.OperationalError:
        row = None
    conn.close()
    if row:
        try:
            records = json.loads(row[0]) if row[0] else []
            spend = float(row[1]) if row[1] is not None else 0.0
            logs = json.loads(row[2]) if row[2] else ["[SYSTEM_INIT] Secure Credential Vault online."]
            apis = json.loads(row[3]) if row[3] else []
            return records, spend, logs, apis
        except Exception:
            pass
    return [], 0.0, [f"[SYSTEM_INIT] Tenant pipeline initialized for [{ws_name}]."], []

def save_credential_to_vault(email, ws_name, service_name, access_key, secret_key, endpoint):
    conn = sqlite3.connect("cloudguard_users.db", check_same_thread=False)
    cursor = conn.cursor()
    masked = "sk-proj-..." + secret_key[-4:] if len(secret_key) > 4 else "********"
    cursor.execute("""
        INSERT OR REPLACE INTO credential_vault (email, workspace_name, service_name, access_key_id, secret_key_masked, endpoint_url)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (email, ws_name, service_name, access_key, masked, endpoint))
    conn.commit()
    conn.close()

def get_vault_credentials(email, ws_name):
    conn = sqlite3.connect("cloudguard_users.db", check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute("SELECT service_name, access_key_id, endpoint_url FROM credential_vault WHERE email = ? AND workspace_name = ?", (email, ws_name))
    rows = cursor.fetchall()
    conn.close()
    return rows

def dispatch_resilient_circuit_breaker(service_name, target_endpoint="https://api.cloud-gateway.internal/v1/throttle"):
    max_retries = 3
    for attempt in range(1, max_retries + 1):
        try:
            if random.random() < 0.05:
                raise ConnectionError("Gateway TCP Timeout")
            return True, f"[RESILIENT_ADAPTER] Attempt {attempt}/{max_retries}: Successfully applied rate-limit policy to [{service_name}] at endpoint [{target_endpoint}]"
        except Exception as e:
            if attempt == max_retries:
                return False, f"[RESILIENT_ADAPTER] CRITICAL: All {max_retries} retry attempts failed for [{service_name}]. Error: {str(e)}. Event pushed to DLQ."
            time.sleep(0.2 * attempt)

# Session State Setup
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
if "user_email" not in st.session_state:
    st.session_state.user_email = ""
if "current_ws" not in st.session_state:
    st.session_state.current_ws = ""

# Transparent Shield Logo SVG Generator
def get_shield_logo_svg(width=38, height=42):
    return f"""
    <svg width="{width}" height="{height}" viewBox="0 0 200 220" fill="none" xmlns="http://www.w3.org/2000/svg" style="vertical-align: middle; display: inline-block;">
        <path d="M100 10L185 45V110C185 155 148 195 100 210C52 195 15 155 15 110V45L100 10Z" fill="url(#shield_grad)" stroke="#93c5fd" stroke-width="6"/>
        <defs>
            <linearGradient id="shield_grad" x1="15" y1="10" x2="185" y2="210" gradientUnits="userSpaceOnUse">
                <stop offset="0%" stop-color="#38bdf8"/>
                <stop offset="50%" stop-color="#0284c7"/>
                <stop offset="100%" stop-color="#1e3a8a"/>
            </linearGradient>
            <linearGradient id="arrow_grad" x1="50" y1="50" x2="150" y2="170" gradientUnits="userSpaceOnUse">
                <stop offset="0%" stop-color="#fbbf24"/>
                <stop offset="100%" stop-color="#ea580c"/>
            </linearGradient>
        </defs>
        <path d="M55 55L105 105H80L135 165" stroke="url(#arrow_grad)" stroke-width="16" stroke-linecap="round" stroke-linejoin="round"/>
        <path d="M115 155L135 165L125 140" stroke="#ea580c" stroke-width="14" stroke-linecap="round" stroke-linejoin="round"/>
    </svg>
    """

# ==================== SECURE AUTHENTICATION GATE ====================
if not st.session_state.authenticated:
    st.markdown("<div style='height: 35px;'></div>", unsafe_allow_html=True)
    _, col_center, _ = st.columns([1, 1.4, 1])
    
    with col_center:
        logo_svg = get_shield_logo_svg(38, 42)
        st.markdown(
            f"""
            <div style="text-align: center; font-family: 'JetBrains Mono', monospace; color: #38bdf8; font-size: 15px; letter-spacing: 0.25em; text-transform: uppercase; margin-bottom: 10px;">
                {logo_svg} &nbsp; CLOUDGUARD SECURE GATEWAY
            </div>
            <div style="text-align: center; font-size: 30px; font-weight: 700; color: #f8fafc; margin-bottom: 6px;">
                Welcome to CloudGuard
            </div>
            <div style="text-align: center; font-size: 14px; color: #94a3b8; margin-bottom: 30px;">
                Autonomous FinOps & Cloud Governance Platform
            </div>
            """,
            unsafe_allow_html=True
        )
        
        auth_mode = st.radio("Gateway Mode", ["Sign In", "Register"], horizontal=True, key="unique_auth_mode_radio", label_visibility="collapsed")
        
        if auth_mode == "Sign In":
            with st.form("unique_login_form_key"):
                input_email = st.text_input("Username / Email", placeholder="user@company.com", key="unique_l_email")
                input_pass = st.text_input("Password", type="password", placeholder="******", key="unique_l_pass")
                submitted = st.form_submit_button("Access Control Plane")
                
                if submitted:
                    # Ignore accidental spaces while preserving existing users' email casing.
                    input_email = input_email.strip()
                    if input_email and input_pass:
                        stored_email = verify_user(input_email, input_pass)
                        if stored_email:
                            st.session_state.authenticated = True
                            st.session_state.user_email = stored_email
                            st.session_state.current_ws = ""
                            st.success("Authentication successful! Loading dashboard...")
                            time.sleep(0.3)
                            st.rerun()
                        else:
                            st.error("Invalid credentials or account does not exist.")
                    else:
                        st.error("Please fill in all required fields.")
        else:
            with st.form("unique_register_form_key"):
                reg_email = st.text_input("New Username / Email", placeholder="user@company.com", key="unique_r_email")
                reg_pass = st.text_input("New Password", type="password", placeholder="******", key="unique_r_pass")
                submitted_reg = st.form_submit_button("Provision Account")
                
                if submitted_reg:
                    reg_email = reg_email.strip()
                    if reg_email and "@" in reg_email and reg_pass:
                        if register_user(reg_email, reg_pass):
                            st.session_state.authenticated = True
                            st.session_state.user_email = reg_email
                            st.session_state.current_ws = ""
                            st.success("Account provisioned successfully! Loading dashboard...")
                            time.sleep(0.3)
                            st.rerun()
                        else:
                            st.error("Email already registered. Please sign in instead.")
                    else:
                        st.error("Please provide a valid email and password.")

else:
    # ==================== MAIN APPLICATION (STRICTLY ISOLATED) ====================

    with st.sidebar:
        st.markdown("### 🏢 Organization Workspace")
        
        persistent_workspaces = get_db_workspaces(st.session_state.user_email)
        
        if not persistent_workspaces:
            st.info("⚠️ No workspaces found. Please create your first custom workspace below.")
            selected_ws = None
        else:
            selected_ws = st.selectbox("Active Tenant", persistent_workspaces, key="unique_ws_selectbox", label_visibility="collapsed")
        
        with st.expander("➕ Customize & Create Workspace", expanded=not persistent_workspaces):
            new_ws_name = st.text_input("New Workspace Name", placeholder="e.g. Production-US-East", key="unique_new_ws_input")
            if st.button("Create Workspace", key="unique_create_ws_btn"):
                if new_ws_name:
                    if add_db_workspace(st.session_state.user_email, new_ws_name):
                        st.success(f"Workspace '{new_ws_name}' created!")
                        time.sleep(0.3)
                        st.rerun()
                    else:
                        st.error("Workspace name already exists.")
                else:
                    st.error("Please enter a valid workspace name.")

        if selected_ws and selected_ws != st.session_state.current_ws:
            st.session_state.current_ws = selected_ws
            rec, spend, logs, apis = load_workspace_state(st.session_state.user_email, selected_ws)
            st.session_state.stream_records = rec
            st.session_state.total_cumulative_spend = spend
            st.session_state.audit_logs = logs
            # APIs must always be selected deliberately by the user after login;
            # do not restore an earlier workspace's selections into this widget.
            st.session_state.selected_apis = []
            st.session_state.last_services = []
            st.session_state["unique_api_multiselect"] = []
            st.session_state.mitigated = False
            st.session_state.auto_pilot_triggered = False
            st.session_state.anomaly_start_time = None
            st.session_state.secured_savings_total = 0.0
            st.session_state.active_anomalous_services = []

        if selected_ws and not st.session_state.current_ws:
            st.session_state.current_ws = selected_ws
            rec, spend, logs, apis = load_workspace_state(st.session_state.user_email, selected_ws)
            st.session_state.stream_records = rec
            st.session_state.total_cumulative_spend = spend
            st.session_state.audit_logs = logs
            st.session_state.selected_apis = []
            st.session_state.last_services = []
            st.session_state["unique_api_multiselect"] = []

        st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)
        st.markdown(
            f"""
            <div class="user-badge">
              <div style="font-size: 10px; color: #94a3b8; text-transform: uppercase; font-family: 'JetBrains Mono', monospace; letter-spacing: 0.1em;">SIGNED IN AS</div>
              <div style="font-size: 13px; font-weight: 600; color: #f8fafc; margin-top: 3px; word-break: break-all;">{st.session_state.user_email}</div>
              <div style="font-size: 11px; color: #38bdf8; margin-top: 4px;">Workspace: {selected_ws if selected_ws else 'None'}</div>
            </div>
            """,
            unsafe_allow_html=True
        )
        
        if st.button("🚪 Sign Out Workspace", key="unique_signout_btn"):
            st.session_state.authenticated = False
            st.session_state.user_email = ""
            st.session_state.current_ws = ""
            st.rerun()

        st.markdown("---")
        st.markdown("### 🔐 Secure Credential Vault")
        
        global_api_database = [
            "OpenAI API Token", "Anthropic Claude API", "Amazon EC2 GPU Cluster",
            "AWS S3 Storage Gateway", "Google Cloud Vertex AI", "Microsoft Azure Cognitive",
            "Stripe Payment Gateway", "Snowflake Data Warehouse", "Datadog Telemetry API",
            "GitHub Enterprise API", "MongoDB Atlas Cloud", "Twilio SMS & Voice API",
        ]

        if "master_api_catalog" not in st.session_state:
            st.session_state.master_api_catalog = global_api_database
        if "selected_apis" not in st.session_state:
            st.session_state.selected_apis = []

        # The selected values live in the widget's session state.  Do not also
        # pass `default`, otherwise a stale widget state can override workspace data.
        selected_services = st.multiselect("Monitored APIs", options=st.session_state.master_api_catalog, key="unique_api_multiselect")

        with st.expander("🔑 Configure API Credentials & Keys"):
            if selected_services:
                target_api_to_config = st.selectbox("Select API to Configure", selected_services, key="vault_target_api")
                vault_access_id = st.text_input("API Access Key / ID", placeholder="AKIAIOSFODNN7EXAMPLE", key="vault_access_input")
                vault_secret_key = st.text_input("API Secret / Token", type="password", placeholder="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", key="vault_secret_input")
                vault_endpoint = st.text_input("Custom Endpoint URL (Optional)", placeholder="https://api.openai.com/v1", key="vault_endpoint_input")
                
                col_save1, col_save2 = st.columns(2)
                with col_save1:
                    if st.button("Save to Vault", key="save_vault_btn"):
                        if target_api_to_config and vault_access_id and vault_secret_key:
                            save_credential_to_vault(st.session_state.user_email, selected_ws, target_api_to_config, vault_access_id, vault_secret_key, vault_endpoint)
                            st.success("Saved!")
                            st.rerun()
                        else:
                            st.error("Provide valid keys.")
                with col_save2:
                    if st.button("⚡ Quick Demo Preset", key="quick_preset_btn"):
                        if target_api_to_config:
                            save_credential_to_vault(st.session_state.user_email, selected_ws, target_api_to_config, "AKIA_DEMO_KEY_9988", "sk-sandbox-demo-token-xyz", "https://api.sandbox.cloudguard.internal")
                            st.success("Demo Preset Applied!")
                            st.rerun()
            else:
                st.info("Select at least one API above.")

        configured_creds = []
        if selected_ws:
            raw_creds = get_vault_credentials(st.session_state.user_email, selected_ws)
            configured_creds = [c[0] for c in raw_creds]
            if raw_creds:
                st.markdown("**Active Vault Linkages:**")
                for c_svc, c_ak, c_ep in raw_creds:
                    st.caption(f"✓ {c_svc} (Key ID: {c_ak[:6]}...)")

        st.markdown("---")
        st.markdown("### ⏱️ Billing Time Window")
        billing_window = st.selectbox("Aggregation Window", ["Last 24 Hours", "Month-to-Date (MTD)", "Year-to-Date (YTD)"], label_visibility="collapsed", key="unique_billing_window")

        if "last_services" not in st.session_state:
            st.session_state.last_services = st.session_state.selected_apis

        if set(selected_services) != set(st.session_state.last_services):
            added = set(selected_services) - set(st.session_state.last_services)
            removed = set(st.session_state.last_services) - set(selected_services)
            if added:
                st.session_state.audit_logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] [VAULT_ROUTER] Bound telemetry stream to APIs: {list(added)}")
            if removed:
                st.session_state.audit_logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] [VAULT_ROUTER] Unbound telemetry stream from APIs: {list(removed)}")
            st.session_state.last_services = selected_services.copy()
            st.session_state.selected_apis = selected_services.copy()

    if "audit_logs" not in st.session_state:
        st.session_state.audit_logs = [f"[{datetime.now().strftime('%H:%M:%S')}] [SYSTEM_INIT] Enterprise FinOps Telemetry Engine online."]
    if "stream_records" not in st.session_state:
        st.session_state.stream_records = []
    if "total_cumulative_spend" not in st.session_state:
        st.session_state.total_cumulative_spend = 0.0
    if "mitigated" not in st.session_state:
        st.session_state.mitigated = False
    if "auto_pilot_triggered" not in st.session_state:
        st.session_state.auto_pilot_triggered = False
    if "anomaly_start_time" not in st.session_state:
        st.session_state.anomaly_start_time = None
    if "secured_savings_total" not in st.session_state:
        st.session_state.secured_savings_total = 0.0
    if "active_anomalous_services" not in st.session_state:
        st.session_state.active_anomalous_services = []

    st.markdown(
        """
    <div class="hero">
      <div class="hero-kicker">CloudGuard &nbsp;·&nbsp; Autonomous FinOps Control Plane</div>
      <h1>Cloud Billing Anomaly Detection & Autonomous Fail-Safe</h1>
      <p>Real-time telemetry monitoring, multi-tier escalation, and autonomous circuit breaking for cloud cost governance.</p>
    </div>
    """,
        unsafe_allow_html=True,
    )

    if not selected_ws:
        st.warning("⚠️ Please create and select an Organization Workspace from the sidebar to start monitoring cloud telemetry.")
        st.stop()

    verified_active_services = [s for s in selected_services if s in configured_creds]

    if selected_services and not verified_active_services:
        st.markdown(
            """
            <div class="alert-box">
              <div class="alert-title">🔒 Secure Credential Guard Active</div>
              <div class="alert-sub">
                You have selected APIs in the catalog, but <strong>no valid API Credentials / Access Keys</strong> have been configured in the Vault for them.<br>
                <em>Please expand <strong>"Configure API Credentials & Keys"</strong> in the sidebar, input your Access ID, or click <strong>⚡ Quick Demo Preset</strong> to instantly initialize streaming.</em>
              </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    if verified_active_services and not st.session_state.stream_records:
        base_time = datetime.now() - timedelta(hours=15)
        initial_records = []
        for i in range(15):
            t = base_time + timedelta(hours=i)
            for s in verified_active_services:
                avg = 55.0 if "GPU" in s else (35.0 if "AI" in s or "OpenAI" in s or "Anthropic" in s else 20.0)
                initial_records.append({
                    "timestamp": t.strftime('%Y-%m-%d %H:%M:%S'),
                    "service_name": s,
                    "current_cost": round(avg * random.uniform(0.9, 1.1), 2),
                    "historical_avg": avg,
                    "is_anomaly": False
                })
        st.session_state.stream_records = initial_records

    is_stopped = st.session_state.mitigated or st.session_state.auto_pilot_triggered

    if verified_active_services:
        latest_time_str = st.session_state.stream_records[-1]["timestamp"] if st.session_state.stream_records else datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        latest_time = datetime.strptime(latest_time_str, '%Y-%m-%d %H:%M:%S')
        next_time = latest_time + timedelta(hours=1)
        active_anomaly_in_tick = False

        if not is_stopped:
            if st.session_state.anomaly_start_time is None and random.random() < 0.35:
                active_anomaly_in_tick = True
                num_rogue = random.randint(1, min(2, len(verified_active_services)))
                st.session_state.active_anomalous_services = random.sample(verified_active_services, k=num_rogue)
                st.session_state.anomaly_start_time = time.time()
                log_msg = f"[{datetime.now().strftime('%H:%M:%S')}] [ANOMALY_DETECTOR] Cost spike detected on {st.session_state.active_anomalous_services}. Threshold exceeded by 450%."
                if log_msg not in st.session_state.audit_logs:
                    st.session_state.audit_logs.append(log_msg)
            elif st.session_state.anomaly_start_time is not None:
                active_anomaly_in_tick = True

        new_tick_costs = []
        all_known_services = list(set([r["service_name"] for r in st.session_state.stream_records] + verified_active_services))
        
        for s in all_known_services:
            avg = 55.0 if "GPU" in s else (35.0 if "AI" in s or "OpenAI" in s or "Anthropic" in s else 20.0)
            cost = avg * random.uniform(0.9, 1.1)
            is_anom = False
            if not is_stopped and s in verified_active_services and active_anomaly_in_tick and s in st.session_state.active_anomalous_services:
                cost = avg * random.uniform(4.5, 9.0)
                is_anom = True
            record = {
                "timestamp": next_time.strftime('%Y-%m-%d %H:%M:%S'),
                "service_name": s,
                "current_cost": round(cost, 2),
                "historical_avg": avg,
                "is_anomaly": is_anom
            }
            st.session_state.stream_records.append(record)
            if s in verified_active_services:
                new_tick_costs.append(cost)

        if new_tick_costs:
            st.session_state.total_cumulative_spend += sum(new_tick_costs)
        if len(st.session_state.stream_records) > 90:
            st.session_state.stream_records = st.session_state.stream_records[-90:]

    if st.session_state.anomaly_start_time is not None and not is_stopped:
        if time.time() - st.session_state.anomaly_start_time > 15:
            st.session_state.auto_pilot_triggered = True
            is_stopped = True
            df_temp = pd.DataFrame(st.session_state.stream_records)
            df_temp["excess"] = (df_temp["current_cost"] - df_temp["historical_avg"]).clip(lower=0)
            st.session_state.secured_savings_total = float(df_temp[df_temp["is_anomaly"]]["excess"].sum())
            
            for rogue_svc in st.session_state.active_anomalous_services:
                success, msg = dispatch_resilient_circuit_breaker(rogue_svc)
                st.session_state.audit_logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")

            st.session_state.audit_logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] [AUTOPILOT_FAILSAFE] Autonomous circuit breaker sequence completed.")

    if is_stopped:
        if st.session_state.anomaly_start_time is not None and time.time() - st.session_state.anomaly_start_time > 28:
            st.session_state.mitigated = False
            st.session_state.auto_pilot_triggered = False
            st.session_state.anomaly_start_time = None
            st.session_state.secured_savings_total = 0.0
            st.session_state.audit_logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] [SYSTEM_RESET] Connector auto-reset for next governance cycle.")

    save_workspace_state(st.session_state.user_email, selected_ws, st.session_state.stream_records, st.session_state.total_cumulative_spend, st.session_state.audit_logs, selected_services)

    df_all = pd.DataFrame(st.session_state.stream_records) if st.session_state.stream_records else pd.DataFrame(columns=["timestamp", "service_name", "current_cost", "historical_avg", "is_anomaly"])
    if not df_all.empty:
        df_all["excess_cost"] = (df_all["current_cost"] - df_all["historical_avg"]).clip(lower=0)
        df_display = df_all[df_all["service_name"].isin(verified_active_services)] if verified_active_services else pd.DataFrame(columns=df_all.columns)
        potential_savings = float(df_display[df_display["is_anomaly"] == True]["excess_cost"].sum()) if not df_display.empty else 0.0
    else:
        df_display = pd.DataFrame()
        potential_savings = 0.0

    window_multiplier = 1.0 if billing_window == "Last 24 Hours" else (14.5 if billing_window == "Month-to-Date (MTD)" else 120.0)
    total_spend = float(st.session_state.total_cumulative_spend * (window_multiplier / 10.0))
    anomalies = df_display.loc[df_display["is_anomaly"]] if not df_display.empty and "is_anomaly" in df_display.columns else pd.DataFrame()
    critical_alerts = 0 if is_stopped or anomalies.empty else int(anomalies[anomalies["timestamp"] == anomalies["timestamp"].max()]["service_name"].nunique())
    secured_savings = st.session_state.secured_savings_total if is_stopped else potential_savings

    m1, m2, m3 = st.columns(3)
    m1.metric("Live Total Spend", f"${total_spend:,.2f}", f"Window: {billing_window}")
    m2.metric("Active Critical Alerts", f"{critical_alerts}", "Mitigated" if is_stopped else "Active", delta_color="off" if is_stopped else "inverse")
    m3.metric("Estimated Cost Savings", f"${secured_savings:,.2f}" if is_stopped else f"${potential_savings:,.2f}", "Secured" if is_stopped else "At risk")

    main_col, side_col = st.columns([2.2, 1])

    with main_col:
        st.markdown('<div class="panel">', unsafe_allow_html=True)
        st.subheader("Real-Time Telemetry & Cost Stream")
        fig = go.Figure()
        color_palette = ["#38bdf8", "#ef4444", "#34d399", "#f43f5e", "#a855f7", "#eab308"]

        if not verified_active_services:
            st.info("💡 Scope Notice: No verified API credentials found in the Secure Vault. Please click '⚡ Quick Demo Preset' in the sidebar to initialize streaming.")
        elif not df_display.empty:
            for idx, (service, group) in enumerate(df_display.groupby("service_name")):
                fig.add_trace(go.Scatter(x=group["timestamp"], y=group["current_cost"], name=service, mode="lines", line=dict(color=color_palette[idx % len(color_palette)], width=2.5)))
        fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(15, 23, 42, 0.45)", font=dict(color="#cbd5e1"), margin=dict(l=8, r=8, t=28, b=8), height=320)
        st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
        st.markdown("</div>", unsafe_allow_html=True)

        col_pie, col_ctrl = st.columns(2)

        with col_pie:
            st.markdown('<div class="panel">', unsafe_allow_html=True)
            st.subheader("📊 Cost Breakdown & Export")
            
            if not df_display.empty:
                df_pie = df_display.groupby("service_name")["current_cost"].sum().reset_index()
                fig_pie = go.Figure(data=[go.Pie(labels=df_pie["service_name"], values=df_pie["current_cost"], hole=.4)])
                fig_pie.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="#cbd5e1"), margin=dict(l=10, r=10, t=10, b=10), height=200)
                st.plotly_chart(fig_pie, use_container_width=True, config={"displayModeBar": False})
            else:
                st.info("No active telemetry data for breakdown.")
            st.markdown("</div>", unsafe_allow_html=True)  # <-- Fixed and closed properly

            st.markdown('<div class="panel">', unsafe_allow_html=True)
            st.subheader("📥 Multi-Format Report Export")
            export_format = st.selectbox("Choose Export Format", ["CSV", "Excel (.xlsx)", "Word (.docx)", "PDF (.pdf)"], key="unique_export_fmt")
            export_df = df_display if not df_display.empty else df_all
            
            if not export_df.empty:
                if export_format == "CSV":
                    csv_data = export_df.to_csv(index=False).encode('utf-8')
                    st.download_button("Download CSV Report", csv_data, "cloudguard_audit_report.csv", "text/csv", use_container_width=True, key="unique_dl_csv")
                elif export_format == "Excel (.xlsx)":
                    output = io.BytesIO()
                    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
                        export_df.to_excel(writer, index=False, sheet_name='Billing Telemetry')
                    excel_data = output.getvalue()
                    st.download_button("Download Excel Report", excel_data, "cloudguard_audit_report.xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", use_container_width=True, key="unique_dl_xlsx")
                elif export_format == "Word (.docx)":
                    doc = Document()
                    doc.add_heading('CloudGuard FinOps Audit & Billing Report', 0)
                    doc.add_paragraph(f'Workspace: {selected_ws} | User: {st.session_state.user_email} | Time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
                    table = doc.add_table(rows=1, cols=4)
                    hdr_cells = table.rows[0].cells
                    hdr_cells[0].text = 'Timestamp'
                    hdr_cells[1].text = 'Service Name'
                    hdr_cells[2].text = 'Cost (USD)'
                    hdr_cells[3].text = 'Anomaly Status'
                    for _, row in export_df.iterrows():
                        row_cells = table.add_row().cells
                        row_cells[0].text = str(row['timestamp'])
                        row_cells[1].text = str(row['service_name'])
                        row_cells[2].text = f"${row['current_cost']:.2f}"
                        row_cells[3].text = "CRITICAL" if row['is_anomaly'] else "Normal"
                    doc_io = io.BytesIO()
                    doc.save(doc_io)
                    doc_io.seek(0)
                    st.download_button("Download Word Report", doc_io, "cloudguard_audit_report.docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", use_container_width=True, key="unique_dl_docx")
                elif export_format == "PDF (.pdf)":
                    pdf_io = io.BytesIO()
                    doc_pdf = SimpleDocTemplate(pdf_io, pagesize=letter)
                    story = []
                    styles = getSampleStyleSheet()
                    story.append(Paragraph("CloudGuard FinOps Audit Report", styles['Title']))
                    story.append(Spacer(1, 10))
                    story.append(Paragraph(f"User: {st.session_state.user_email} | Workspace: {selected_ws}", styles['Normal']))
                    story.append(Spacer(1, 15))
                    table_data = [["Timestamp", "Service Name", "Cost ($)", "Status"]]
                    for _, row in export_df.iterrows():
                        table_data.append([str(row['timestamp']), str(row['service_name']), f"${row['current_cost']:.2f}", "ANOMALY" if row['is_anomaly'] else "Normal"])
                    t = Table(table_data, colWidths=[110, 140, 70, 80])
                    t.setStyle(TableStyle([
                        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1e293b')),
                        ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
                        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
                        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                        ('BOTTOMPADDING', (0,0), (-1,0), 6),
                        ('GRID', (0,0), (-1,-1), 0.5, colors.grey)
                    ]))
                    story.append(t)
                    doc_pdf.build(story)
                    pdf_io.seek(0)
                    st.download_button("Download PDF Report", pdf_io, "cloudguard_audit_report.pdf", "application/pdf", use_container_width=True, key="unique_dl_pdf")
            else:
                st.info("No records to export.")
            st.markdown("</div>", unsafe_allow_html=True)  # <-- Fixed and closed properly

        with col_ctrl:
            st.markdown('<div class="panel">', unsafe_allow_html=True)
            st.subheader("🚨 Incident Response & Autonomous Fail-Safe")
            
            if not verified_active_services:
                st.info("System scope idle. Configure credentials in Vault.")
            elif is_stopped:
                st.markdown(
                    f"""
    <div class="ok-box">
      <strong>{ 'Autonomous Circuit Breaker Tripped' if st.session_state.auto_pilot_triggered else 'Manual Stop-Loss Executed' }</strong><br>
      API Billing Throttled & Rate-Limited. Secured: <strong>${secured_savings:,.2f}</strong>.<br>
      <em>Policy: Automated Gateway Rate-Limiting Active. System streaming normal telemetry.</em>
    </div>
    """,
                    unsafe_allow_html=True,
                )
            else:
                if anomalies.empty or st.session_state.anomaly_start_time is None:
                    st.info("System healthy. Polling live telemetry stream...")
                else:
                    elapsed = time.time() - st.session_state.anomaly_start_time
                    remaining = max(0, int(15 - elapsed))
                    rogue_str = " & ".join(st.session_state.active_anomalous_services)
                    
                    st.markdown(
                        f"""
    <div class="alert-box">
      <div class="alert-title">🚨 Billing Anomaly & Cost Spike Detected</div>
      <div class="alert-sub">
        [<strong>{rogue_str}</strong>] abnormal exposure: ${potential_savings:,.2f}.<br>
        <em>AI autonomous circuit breaker engaging in T-minus 00:{remaining:02d}.</em>
      </div>
    </div>
    """,
                        unsafe_allow_html=True,
                    )

                    if st.button("🚨 Execute Instant Stop-Loss", type="primary", key="unique_stop_loss_btn"):
                        st.session_state.mitigated = True
                        st.session_state.secured_savings_total = potential_savings
                        
                        for rogue_svc in st.session_state.active_anomalous_services:
                            success, msg = dispatch_resilient_circuit_breaker(rogue_svc)
                            st.session_state.audit_logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")

                        st.session_state.audit_logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] [MANUAL_MITIGATION] Operator executed instant stop-loss with resilient retry.")
                        st.toast("Stop-loss executed with retry verification.", icon="✅")
                        st.rerun()
            st.markdown("</div>", unsafe_allow_html=True)  # <-- Fixed and closed properly

    with side_col:
        st.markdown('<div class="panel">', unsafe_allow_html=True)
        st.subheader("📋 Audit Trail & Governance Logs")
        log_text = "\n".join(st.session_state.audit_logs[-18:])
        st.markdown(f'<div class="terminal-box">{log_text.replace(chr(10), "<br>")}</div>', unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)

    # Browser-side timer: keeps telemetry moving without holding the Python run
    # open (which is what produced the dark Streamlit running overlay).
    if verified_active_services:
        st_autorefresh(interval=3000, limit=None, key="cloudguard_live_stream")