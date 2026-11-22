import streamlit as st
import socket
import requests
import os
import ipaddress
from core.traffic_analyzer import capture_traffic
from core.risk_assessment import extract_open_ports, analyze_risks, calculate_risk
import re
import subprocess
import shutil
from dotenv import load_dotenv

# ==========================================
# 1. PAGE CONFIGURATION
# ==========================================

st.set_page_config(
    page_title="Cyber Defense SOC Lab",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Local Agent Configuration
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), ".env"), override=True)
AGENT_URL = "http://127.0.0.1:8000"
# عنوان خادم Cloudflare المسؤول عن نقل الأوامر بين الموقع وأجهزة الطلاب
RELAY_URL = "https://solitary-hall-00cf.hawraaraed69.workers.dev"
# معرّف الطالب الذي يحدد الجهاز المطلوب إرسال أمر الفحص إليه
STUDENT_ID = os.getenv("STUDENT_ID", "student01")
# بيانات مصادقة الطالب الخاصة بكل جلسة
# حقل إدخال رمز الطالب ليظهر في واجهة المختبر
STUDENT_TOKEN = st.text_input(
    "Student Token",
    type="password",
    key="student_token_input"
)
# تحميل مفتاح المصادقة الخاص بتطبيق Streamlit للاتصال بخادم Relay
# يُقرأ من إعدادات Streamlit Cloud أو من متغيرات البيئة عند التشغيل المحلي
try:
    RELAY_APP_SECRET = st.secrets.get("APP_SECRET", os.getenv("APP_SECRET", ""))
except Exception:
    RELAY_APP_SECRET = os.getenv("APP_SECRET", "")
AGENT_TOKEN = os.getenv("SOC_AGENT_TOKEN")
st.write("Token loaded:", bool(AGENT_TOKEN))

# ==========================================
# 2. SOC THEME
# ==========================================

st.markdown("""
<style>

.stApp {
    background-color: #0E1117;
    color: #E0E0E0;
}

section[data-testid="stSidebar"] {
    background-color: #111927;
}

.soc-title {
    color: #00E5FF;
    font-size: 27px;
    font-weight: bold;
}

.soc-card {
    background-color: #1A2332;
    padding: 20px;
    border-radius: 12px;
    border: 1px solid #26364A;
    margin-bottom: 12px;
}

.metric-label {
    color: #8FA3B8;
    font-size: 13px;
}

.metric-value {
    color: #00E5FF;
    font-size: 27px;
    font-weight: bold;
}

div.stButton > button {
    background-color: #007C91;
    color: white;
    border: none;
    border-radius: 8px;
    padding: 8px 20px;
}

div.stButton > button:hover {
    background-color: #00A6BD;
    color: white;
}

</style>
""", unsafe_allow_html=True)

# ==========================================
# 3. SIDEBAR
# ==========================================

with st.sidebar:
    st.markdown("## 🛡️ SOC CONTROL PANEL")

    st.success("SYSTEM STATUS: ONLINE")

    st.markdown("---")

    st.markdown("**Target Environment**")
    st.info("Secure Lab")

    st.markdown("**Developer**")
    st.write("Cyber Security Student")

    st.markdown("**Version**")
    st.write("2.6.0 | SOC Edition")

    st.markdown("---")

    st.caption("Cyber Defense Operations Lab")

# ==========================================
# 4. MAIN HEADER
# ==========================================

st.markdown(
    '<p class="soc-title">🌐 ENTERPRISE CYBERSECURITY OPERATIONS LAB</p>',
    unsafe_allow_html=True
)

st.caption(
    "Network Reconnaissance | Traffic Analysis | Security Monitoring"
)

st.markdown("---")

# ==========================================
# 5. SOC DASHBOARD METRICS
# ==========================================

col1, col2, col3, col4 = st.columns(4)

with col1:
    st.markdown("""
    <div class="soc-card">
        <div class="metric-label">GLOBAL THREAT LEVEL</div>
        <div class="metric-value">LOW</div>
        <div>Demo Indicator</div>
    </div>
    """, unsafe_allow_html=True)

with col2:
    st.markdown("""
    <div class="soc-card">
        <div class="metric-label">ACTIVE THREATS</div>
        <div class="metric-value">0</div>
        <div>Demo Indicator</div>
    </div>
    """, unsafe_allow_html=True)

with col3:
    st.markdown("""
    <div class="soc-card">
        <div class="metric-label">NETWORK TRAFFIC</div>
        <div class="metric-value">--</div>
        <div>Awaiting Capture</div>
    </div>
    """, unsafe_allow_html=True)

with col4:
    st.markdown("""
    <div class="soc-card">
        <div class="metric-label">SYSTEM HEALTH</div>
        <div class="metric-value">--</div>
        <div>Not Connected</div>
    </div>
    """, unsafe_allow_html=True)

st.markdown("---")

# ==========================================
# 6. MAIN TABS
# ==========================================

tab1, tab2, tab3, tab4 = st.tabs([
    "🔍 Nmap Reconnaissance",
    "📦 Wireshark Traffic",
    "🧾 Banner Grabbing",
    "📄 PDF Reports"
])

# ==========================================
# TAB 1: NMAP SCANNER
# ==========================================
with tab1:
    st.subheader("🔍 Nmap Network Scanner")

    st.write(
        "Scan authorized hosts and inspect open ports and services."
    )

    # إدخال عنوان الجهاز المستهدف
    target_ip = st.text_input(
        "Target IP / Host",
        value="127.0.0.1",
        key="nmap_target"
    )

    # اختيار خيارات فحص Nmap
    selected_options = st.multiselect(
        "Select Nmap Scan Options",
        options=[
            "-sS", "-sT", "-sV", "-sC",
            "-O", "-A", "-Pn", "-sn",
            "-sU", "-F", "-T2", "-T3", "-T4"
        ],
        default=["-sV"],
        key="nmap_options"
    )

    # منع اختيار نوعي TCP المتعارضين
    if "-sS" in selected_options and "-sT" in selected_options:
        st.error("Choose either -sS or -sT, not both.")
        st.stop()

    if st.button("🚀 Start Nmap Scan", key="nmap_scan_button"):

        # التحقق من توافق خيارات الفحص
        validation_errors = []

        if "-sS" in selected_options and "-sT" in selected_options:
            validation_errors.append(
                "-sS and -sT cannot be selected together."
            )

        if "-sn" in selected_options:
            incompatible = {
                "-sS", "-sT", "-sU", "-sV",
                "-sC", "-O", "-A", "-F"
            }

            if incompatible.intersection(selected_options):
                validation_errors.append(
                    "-sn cannot be combined with port scanning options."
                )

        timing_options = {"-T2", "-T3", "-T4"}

        if len(timing_options.intersection(selected_options)) > 1:
            validation_errors.append(
                "Choose only one timing option."
            )

        # إيقاف الفحص عند وجود خيارات غير متوافقة
        if validation_errors:
            for error in validation_errors:
                st.error(error)
            st.stop()

        # التأكد من وجود مفتاح الاتصال السحابي
        if not RELAY_APP_SECRET:
            st.warning("Cloudflare connection is not configured.")

        else:
            try:
                # التحقق من صحة عنوان IP
                ip = ipaddress.ip_address(target_ip)

                with st.spinner("Scanning target..."):

                    # إرسال أمر الفحص إلى Cloudflare Relay
                    response = requests.post(
                        f"{RELAY_URL}/command",
                        json={
                            "student_id": STUDENT_ID,"student_token":STUDENT_TOKEN,

                            "action": "scan",
                            "payload": {
                                "target": str(ip),
                                "options": selected_options or ["-sV"]
                            }
                        },
                        headers={
                            "Authorization": f"Bearer {RELAY_APP_SECRET}"
                        },
                        timeout=190
                    )

                    response.raise_for_status()
                    relay_result = response.json()

                # التحقق من نتيجة الاتصال بالـ Relay
                if relay_result.get("error"):
                    st.error(relay_result["error"])

                else:
                    results = relay_result.get("data", {})

                    # التحقق من نتيجة تنفيذ Nmap
                    if results.get("error"):
                        st.error(f"Scan Error: {results['error']}")

                    else:
                        nmap_output = results.get("output", "")

                        st.success("Scan completed successfully!")
                        st.code(nmap_output, language="text")

                        # تحليل المنافذ المفتوحة وتقييم المخاطر
                        open_ports = extract_open_ports(nmap_output)
                        findings = analyze_risks(open_ports)
                        risk = calculate_risk(findings)

                        st.subheader("Security Risk Assessment")

                        st.metric(
                            "Risk Indicator Score",
                            f"{risk['score']}/100"
                        )

                        st.caption(
                            "Score is based on predefined risk indicators, "
                            "not a confirmed vulnerability or breach probability."
                        )

                        # عرض مستوى المخاطر
                        if risk["level"] == "High":
                            st.error(f"Risk Level: {risk['level']}")

                        elif risk["level"] == "Medium":
                            st.warning(f"Risk Level: {risk['level']}")

                        elif risk["level"] == "No Indicators":
                            st.info(
                                "No known risk indicators detected by current rules."
                            )

                        else:
                            st.success(f"Risk Level: {risk['level']}")

                        # عرض المشكلات الأمنية المكتشفة
                        if findings:
                            st.markdown("### Detected Security Issues")

                            for item in findings:
                                with st.container(border=True):
                                    st.markdown(
                                        f"**Port {item['port']} — {item['service']}**"
                                    )

                                    st.caption(
                                        f"Service Version: {item.get('version', 'Unknown')}"
                                    )

                                    st.error(f"Risk Level: {item['risk']}")
                                    st.write(f"Reason: {item['reason']}")

                                    st.info(
                                        f"Recommendation: {item['recommendation']}"
                                    )

                        else:
                            st.success(
                                "No known risk indicators detected."
                            )

            except ValueError:
                st.error("Please enter a valid IP address.")

            except requests.exceptions.RequestException as e:
                st.error(f"Relay connection error: {e}")

    st.caption(
        "Only scan systems you own or have permission to test."
    )


# ==========================================
# TAB 2: WIRESHARK / TSHARK
# ==========================================
with tab2:
    st.subheader("📦 Network Traffic Capture")
    st.write("Capture real network packets using local Wireshark TShark.")

    col1, col2 = st.columns(2)

    # اختيار واجهة الشبكة على جهاز الطالب
    interface = st.selectbox(
        "Select Network Interface",
        [5, 9, 8],
        format_func=lambda x: {
            5: "Wi-Fi",
            9: "Ethernet",
            8: "Loopback"
        }[x]
    )

    # تحديد عدد الحزم
    packet_count = st.number_input(
        "Number of Packets",
        min_value=1,
        max_value=100,
        value=20,
        step=1
    )

    if st.button("📡 Capture Network Packets", key="capture_packets_button"):

        if not RELAY_APP_SECRET:
            st.error("Relay authentication is not configured.")

        else:
            try:
                with st.spinner("Capturing packets on your device..."):

                    response = requests.post(
                        f"{RELAY_URL}/command",
                        json={
                        "student_id": STUDENT_ID,
                        "student_token": STUDENT_TOKEN,
                        "action": "capture",
                        "payload": {
                        "interface": interface,
                        "count": int(packet_count)
                            }

                        } ,
                        headers={
                            "Authorization": f"Bearer {RELAY_APP_SECRET}"
                        },
                        timeout=150
                    )

                    response.raise_for_status()
                    relay_result = response.json()

                if relay_result.get("error"):
                    st.error(relay_result["error"])

                else:
                    results = relay_result.get("data", {}).get("packets", [])

                    if results:
                        st.success(f"Captured {len(results)} packets.")
                        st.dataframe(results, use_container_width=True)

                        total_bytes = sum(
                            int(packet["length"])
                            for packet in results
                            if str(packet["length"]).isdigit()
                        )

                        col1, col2 = st.columns(2)

                        col1.metric("Total Packets", len(results))
                        col2.metric("Total Data (Bytes)", total_bytes)

                    else:
                        st.warning("No packets were returned.")

            except requests.exceptions.RequestException as e:
                st.error(f"Capture request failed: {e}")

# =========================================
# TAB 3: BANNER GRABBING
# =========================================

with tab3:
    st.subheader("🧾 Banner Grabbing")

    st.write(
        "Retrieve service information from an authorized target."
    )

    banner_ip = st.text_input(
        "Target IP",
        value="127.0.0.1",
        key="banner_ip"
    )

    banner_port = st.number_input(
        "Target Port",
        min_value=1,
        max_value=65535,
        value=80,
        key="banner_port"
    )

    if st.button(
            "🔎 Grab Service Banner",
            key="banner_grab_button"
    ):

        try:
            with socket.create_connection(
                    (banner_ip, int(banner_port)),
                    timeout=5
            ) as connection:

                connection.sendall(
                    b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n"
                )

                banner = connection.recv(4096).decode(
                    "utf-8",
                    errors="replace"
                )

                if banner:
                    server_match = re.search(
                        r"(?im)^Server:\s*(.+)$",
                        banner
                    )

                    if server_match:
                        server_info = server_match.group(1).strip()
                        st.write("**Detected Server:**", server_info)
                    else:
                        st.info("Server information was not disclosed.")

                    st.success("Response received!")
                    st.code(banner)
                else:
                    st.warning("No banner returned.")

        except (OSError, ValueError) as e:
            st.error(f"Connection failed: {e}")

    st.caption(
        "Use only on systems you own or have permission to test."
    )

# ==========================================
# TAB 4: PDF REPORTS
# ==========================================

with tab4:
    st.subheader("📄 Automated PDF Reports")

    st.write(
        "Generate professional security assessment reports."
    )

    st.info(
        "PDF report generation will be implemented in the next phase."
    )

    st.markdown("### Planned Report Features")

    st.write("- Nmap scan results")
    st.write("- Open ports and detected services")
    st.write("- Network traffic analysis")
    st.write("- Report timestamp")
    st.write("- Security assessment summary")

# ==========================================
# 7. FOOTER
# ==========================================

st.markdown("---")

st.caption(
    "Cyber Defense SOC Lab | Educational and Authorized Security Testing"
)
