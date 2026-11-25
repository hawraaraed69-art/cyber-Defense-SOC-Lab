import ipaddress
import os
from datetime import datetime

import requests
import streamlit as st
from dotenv import load_dotenv

try:
    from core.risk_assessment import (
        analyze_risks,
        calculate_risk,
        extract_open_ports,
    )
except ImportError:
    def extract_open_ports(_output: str):
        return []

    def analyze_risks(_ports):
        return []

    def calculate_risk(_findings):
        return {"score": 0, "level": "No Indicators"}


# =========================================================
# 1. PAGE CONFIGURATION
# =========================================================

st.set_page_config(
    page_title="Cyber Defense SOC Lab",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# =========================================================
# 2. LOCAL CONFIGURATION
# =========================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(BASE_DIR, ".env"), override=False)

LOCAL_AGENT_URL = os.getenv(
    "LOCAL_AGENT_URL",
    "http://127.0.0.1:8000",
).rstrip("/")

ENV_STUDENT_ID = os.getenv("STUDENT_ID", "").strip()
ENV_AGENT_TOKEN = os.getenv("SOC_AGENT_TOKEN", "").strip()

NMAP_OPTIONS = [
    "-sS", "-sT", "-sV", "-sC",
    "-O", "-A", "-Pn", "-sn",
    "-sU", "-F", "-T2", "-T3", "-T4",
]


# =========================================================
# 3. SESSION STATE
# =========================================================

DEFAULT_STATE = {
    "authenticated": False,
    "student_id": "",
    "agent_token": "",
    "last_scan": None,
    "last_capture": [],
    "network_interfaces": [],
    "last_risk": None,
    "last_findings": [],
}

for state_key, default_value in DEFAULT_STATE.items():
    if state_key not in st.session_state:
        st.session_state[state_key] = default_value


# =========================================================
# 4. LOCAL AGENT COMMUNICATION
# =========================================================

def _build_headers(token: str = "") -> dict:
    headers = {}
    clean_token = (token or "").strip()
    if clean_token:
        headers["Authorization"] = f"Bearer {clean_token}"
    return headers


def call_local_agent(
    method: str,
    endpoint: str,
    token: str = "",
    params: dict | None = None,
    timeout: int = 150,
) -> dict:
    """إرسال طلب مباشر إلى Local Agent على جهاز المستخدم."""
    url = f"{LOCAL_AGENT_URL}{endpoint}"
    headers = _build_headers(token)

    try:
        response = requests.request(
            method=method.upper(),
            url=url,
            params=params,
            headers=headers,
            timeout=timeout,
        )
    except requests.ConnectionError:
        raise RuntimeError(
            f"Cannot connect to Local Agent at {LOCAL_AGENT_URL}. "
            "Make sure local_agent.py is running on your computer."
        )
    except requests.Timeout:
        raise RuntimeError("Local Agent request timed out.")
    except requests.RequestException as error:
        raise RuntimeError(f"Network error talking to Local Agent: {error}")

    try:
        data = response.json()
    except ValueError:
        response.raise_for_status()
        raise RuntimeError("Local Agent returned a non-JSON response.")

    if response.status_code >= 400:
        detail = data.get("detail") or data.get("error") or response.text
        raise RuntimeError(f"Agent HTTP {response.status_code}: {detail}")

    if isinstance(data, dict) and data.get("error"):
        raise RuntimeError(str(data["error"]))

    if not isinstance(data, dict):
        raise RuntimeError("Local Agent returned an unexpected response format.")

    return data


# =========================================================
# 5. VALIDATION HELPERS
# =========================================================

def validate_target_ip(value: str) -> str:
    """التحقق من صحة عنوان IP."""
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except (ValueError, AttributeError):
        raise ValueError("Enter a valid IPv4 or IPv6 address.")


def validate_nmap_options(options: list[str]) -> list[str]:
    errors = []

    scan_types = {"-sS", "-sT", "-sU"}
    if len(scan_types.intersection(options)) > 1:
        errors.append("Select only one scan technique: -sS, -sT, or -sU.")

    if "-sn" in options:
        port_scan_options = {
            "-sS", "-sT", "-sU", "-sV", "-sC", "-O", "-A", "-F"
        }
        if port_scan_options.intersection(options):
            errors.append(
                "-sn is a host-discovery scan and cannot be combined "
                "with port-scan options."
            )

    timing_options = {"-T2", "-T3", "-T4"}
    if len(timing_options.intersection(options)) > 1:
        errors.append("Select only one timing option: -T2, -T3, or -T4.")

    return errors


# =========================================================
# 6. SOC THEME
# =========================================================

st.markdown("""
<style>
.stApp { background-color: #0E1117; color: #E0E0E0; }
section[data-testid="stSidebar"] { background-color: #111927; }
.soc-title { color: #00E5FF; font-size: 27px; font-weight: bold; }
.soc-card {
    background-color: #1A2332;
    padding: 20px;
    border-radius: 12px;
    border: 1px solid #26364A;
    margin-bottom: 12px;
}
.metric-label { color: #8FA3B8; font-size: 13px; }
.metric-value { color: #00E5FF; font-size: 27px; font-weight: bold; }
div.stButton > button {
    background-color: #007C91;
    color: white;
    border: none;
    border-radius: 8px;
    padding: 8px 20px;
}
div.stButton > button:hover { background-color: #00A6BD; color: white; }
</style>
""", unsafe_allow_html=True)


# =========================================================
# 7. SIDEBAR
# =========================================================

with st.sidebar:
    st.markdown("## 🛡️ SOC CONTROL PANEL")

    if st.session_state.authenticated:
        st.success("LOCAL AGENT: CONNECTED")
        st.caption(f"Student: {st.session_state.student_id}")
        if st.button("Sign out", key="sign_out_button"):
            for key, value in DEFAULT_STATE.items():
                st.session_state[key] = value
            st.rerun()
    else:
        st.warning("LOCAL AGENT: NOT CONNECTED")

    st.markdown("---")
    st.markdown("**Execution Mode**")
    st.info("Local Lab (127.0.0.1)")
    st.markdown("**Version**")
    st.write("3.1.0 | Local SOC Edition")
    st.markdown("---")
    st.caption("Cyber Defense Operations Lab")


# =========================================================
# 8. MAIN HEADER AND LOCAL LOGIN
# =========================================================

st.markdown(
    '<p class="soc-title">🌐 ENTERPRISE CYBERSECURITY OPERATIONS LAB</p>',
    unsafe_allow_html=True,
)
st.caption("Network Reconnaissance | Traffic Analysis | Security Monitoring")
st.markdown("---")

if not st.session_state.authenticated:
    st.subheader("🔐 Student Local Session")
    st.write(
        "Make sure `local_agent.py` is running on your computer, "
        "then connect to start the lab."
    )

    with st.form("student_login_form"):
        login_student_id = st.text_input(
            "Student ID",
            value=ENV_STUDENT_ID,
            max_chars=64,
        )
        login_agent_token = st.text_input(
            "Agent Token (if configured in .env)",
            value=ENV_AGENT_TOKEN,
            type="password",
            max_chars=128,
        )
        login_submitted = st.form_submit_button("Connect to Local Agent")

    if login_submitted:
        clean_id = login_student_id.strip() or "Student"
        clean_token = login_agent_token.strip()

        try:
            with st.spinner("Connecting to Local Agent..."):
                health_data = call_local_agent(
                    "GET",
                    "/health",
                    token=clean_token,
                    timeout=10,
                )
                if clean_token:
                    call_local_agent(
                        "GET",
                        "/protected",
                        token=clean_token,
                        timeout=10,
                    )

                interfaces = []
                try:
                    iface_data = call_local_agent(
                        "GET",
                        "/interfaces",
                        token=clean_token,
                        timeout=20,
                    )
                    interfaces = iface_data.get("interfaces", [])
                except Exception:
                    interfaces = []

            st.session_state.authenticated = True
            st.session_state.student_id = clean_id
            st.session_state.agent_token = clean_token
            st.session_state.network_interfaces = interfaces

            if not health_data.get("nmap_available"):
                st.warning("Local Agent is online, but Nmap was not detected in PATH.")
            if not health_data.get("tshark_available"):
                st.warning("Local Agent is online, but TShark was not detected.")

            st.success("Connected to Local Agent successfully.")
            st.rerun()

        except Exception as error:
            st.error(f"Connection failed: {error}")

    st.stop()


# =========================================================
# 9. DASHBOARD METRICS
# =========================================================

scan_done = st.session_state.last_scan is not None
packet_total = len(st.session_state.last_capture)
risk_data = st.session_state.last_risk or {}
risk_level = risk_data.get("level", "Not assessed")

col1, col2, col3, col4 = st.columns(4)

with col1:
    st.markdown(
        f'<div class="soc-card"><div class="metric-label">LAST SCAN</div>'
        f'<div class="metric-value">{"DONE" if scan_done else "--"}</div>'
        f'<div>{"Nmap result saved" if scan_done else "Awaiting scan"}</div></div>',
        unsafe_allow_html=True,
    )
with col2:
    st.markdown(
        f'<div class="soc-card"><div class="metric-label">RISK LEVEL</div>'
        f'<div class="metric-value">{risk_level}</div>'
        f'<div>Based on current assessment rules</div></div>',
        unsafe_allow_html=True,
    )
with col3:
    st.markdown(
        f'<div class="soc-card"><div class="metric-label">CAPTURED PACKETS</div>'
        f'<div class="metric-value">{packet_total}</div>'
        f'<div>In this session</div></div>',
        unsafe_allow_html=True,
    )
with col4:
    st.markdown(
        '<div class="soc-card"><div class="metric-label">AGENT STATUS</div>'
        '<div class="metric-value">ONLINE</div>'
        '<div>Local host session</div></div>',
        unsafe_allow_html=True,
    )

st.markdown("---")


# =========================================================
# 10. MAIN TABS
# =========================================================

tab1, tab2 = st.tabs([
    "🔍 Nmap Reconnaissance",
    "📦 Wireshark Traffic",
])


# =========================================================
# TAB 1: NMAP
# =========================================================

with tab1:
    st.subheader("🔍 Nmap Network Scanner")
    st.write("Scan authorized hosts and inspect open ports and services.")

    target_ip = st.text_input(
        "Target IP",
        value="127.0.0.1",
        key="nmap_target",
    )

    selected_options = st.multiselect(
        "Select Nmap Scan Options",
        options=NMAP_OPTIONS,
        default=["-sV"],
        key="nmap_options",
        help="Some scan types may require Nmap/Npcap permissions on your computer.",
    )

    if st.button("🚀 Start Nmap Scan", key="nmap_scan_button"):
        try:
            target = validate_target_ip(target_ip)
            validation_errors = validate_nmap_options(selected_options)

            if validation_errors:
                for message in validation_errors:
                    st.error(message)
            else:
                options_to_run = selected_options or ["-sV"]
                with st.spinner("Running Nmap on your computer..."):
                    results = call_local_agent(
                        "POST",
                        "/scan",
                        token=st.session_state.agent_token,
                        params={
                            "target": target,
                            "options": options_to_run,
                        },
                        timeout=160,
                    )

                output = results.get("output", "")
                if not output:
                    st.warning("The scan completed but returned no output.")
                else:
                    open_ports = extract_open_ports(output)
                    findings = analyze_risks(open_ports)
                    risk = calculate_risk(findings)

                    st.session_state.last_scan = {
                        "target": target,
                        "options": options_to_run,
                        "output": output,
                        "timestamp": datetime.now().astimezone().isoformat(),
                    }
                    st.session_state.last_findings = findings
                    st.session_state.last_risk = risk

                    st.success("Nmap scan completed.")
                    st.code(output, language="text")

                    st.subheader("Security Risk Assessment")
                    st.metric("Risk Indicator Score", f"{risk.get('score', 0)}/100")
                    st.caption(
                        "This score is based on predefined indicators. "
                        "It is not proof of a vulnerability or compromise."
                    )

                    level = risk.get("level", "No Indicators")
                    if level == "High":
                        st.error(f"Risk Level: {level}")
                    elif level == "Medium":
                        st.warning(f"Risk Level: {level}")
                    elif level == "No Indicators":
                        st.info("No known risk indicators detected by current rules.")
                    else:
                        st.success(f"Risk Level: {level}")

                    if findings:
                        st.markdown("### Detected Security Issues")
                        for item in findings:
                            with st.container(border=True):
                                st.markdown(
                                    f"**Port {item.get('port')} — {item.get('service')}**"
                                )
                                st.caption(
                                    f"Service Version: {item.get('version', 'Unknown')}"
                                )
                                st.write(f"Risk: {item.get('risk', 'Unknown')}")
                                st.write(f"Reason: {item.get('reason', '')}")
                                st.info(
                                    f"Recommendation: {item.get('recommendation', '')}"
                                )
                    else:
                        st.success("No known risk indicators detected.")

        except ValueError as error:
            st.error(str(error))
        except Exception as error:
            st.error(f"Nmap request failed: {error}")

    st.caption("Only scan systems you own or have explicit permission to test.")


# =========================================================
# TAB 2: WIRESHARK / TSHARK
# =========================================================

with tab2:
    st.subheader("📦 Network Traffic Capture")
    st.write("Capture real packets through TShark on your computer.")

    if st.button("🔄 Refresh Network Interfaces", key="refresh_interfaces"):
        try:
            with st.spinner("Loading interfaces from your computer..."):
                data = call_local_agent(
                    "GET",
                    "/interfaces",
                    token=st.session_state.agent_token,
                    timeout=20,
                )
            st.session_state.network_interfaces = data.get("interfaces", [])
            if st.session_state.network_interfaces:
                st.success("Network interfaces loaded.")
            else:
                st.warning("No interfaces were returned. Check TShark/Npcap.")
        except Exception as error:
            st.error(f"Interface loading failed: {error}")

    interfaces = st.session_state.network_interfaces

    if interfaces:
        selected_interface = st.selectbox(
            "Select Network Interface",
            options=interfaces,
            format_func=lambda item: f"{item.get('id', '?')} - {item.get('name', 'Unknown')}",
            key="capture_interface",
        )
    else:
        selected_interface = None
        st.info("Refresh network interfaces before starting a capture.")

    packet_count = st.number_input(
        "Number of Packets",
        min_value=1,
        max_value=100,
        value=20,
        step=1,
        key="packet_count",
    )

    if st.button("📡 Capture Network Packets", key="capture_packets_button"):
        if not selected_interface:
            st.error("Select a network interface first.")
        else:
            try:
                with st.spinner("Capturing packets on your computer..."):
                    data = call_local_agent(
                        "POST",
                        "/capture",
                        token=st.session_state.agent_token,
                        params={
                            "interface": selected_interface.get("id"),
                            "count": int(packet_count),
                        },
                        timeout=160,
                    )

                packets = data.get("packets", [])
                st.session_state.last_capture = packets

                if packets:
                    st.success(f"Captured {len(packets)} packets.")
                    st.dataframe(packets, use_container_width=True)

                    total_bytes = 0
                    for packet in packets:
                        try:
                            total_bytes += int(packet.get("length", 0))
                        except (TypeError, ValueError):
                            pass

                    metric_col1, metric_col2 = st.columns(2)
                    metric_col1.metric("Total Packets", len(packets))
                    metric_col2.metric("Total Data (Bytes)", total_bytes)
                else:
                    st.warning("The capture returned no packets.")

            except Exception as error:
                st.error(f"Capture failed: {error}")


# =========================================================
# 11. FOOTER
# =========================================================

st.markdown("---")
st.caption(
    "Cyber Defense SOC Lab | Educational and Authorized Security Testing"
)
