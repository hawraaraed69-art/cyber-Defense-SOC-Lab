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
AGENT_URL = "http://127.0.0.1:8000"
AGENT_TOKEN = os.getenv("SOC_AGENT_TOKEN")

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

    target_ip = st.text_input(
        "Target IP / Host",
        value="127.0.0.1",
        key="nmap_target"
    )

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
    if "-sS" in selected_options and "-sT" in selected_options:
        st.error("Choose either -sS or -sT, not both.")
        st.stop()
    if st.button(
            "🚀 Start Nmap Scan",
            key="nmap_scan_button"
    ):

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

        if validation_errors:
            for error in validation_errors:
                st.error(error)

            st.stop()
        if not AGENT_TOKEN:
            st.error("SOC_AGENT_TOKEN is not configured.")

        else:
            try:
                ip = ipaddress.ip_address(target_ip)

                if not ip.is_private:
                    st.error("Only private IP addresses are allowed.")

                else:
                    with st.spinner("Scanning target..."):
                        response = requests.post(
                            f"{AGENT_URL}/scan",
                            params={
                                "target": str(ip),
                                "options": selected_options or ["-sV"]
                            },
                            headers={
                                "Authorization": f"Bearer {AGENT_TOKEN}"
                            },
                            timeout=190
                        )

                    if response.status_code == 200:
                        results = response.json()

                        st.success("Scan completed successfully!")

                        st.code(
                            results.get("output", "No output returned."),
                            language="text"
                        )

                        if results.get("error"):
                            st.error(f"Scan Error: {results['error']}")

                        else:
                            nmap_output = results.get("output", "")

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
                        if risk["level"] == "High":
                            st.error(f"Risk Level: {risk['level']}")

                        elif risk["level"] == "Medium":
                            st.warning(f"Risk Level: {risk['level']}")

                        elif risk["level"] == "No Indicators":
                            st.info("No known risk indicators detected by current rules.")

                        else:
                            st.success(f"Risk Level: {risk['level']}")

                        if findings:
                            st.markdown("### Detected Security Issues")

                            for item in findings:
                                with st.container(border=True):
                                    st.markdown(
                                        f"**Port {item['port']} — {item['service']}**"
                                    )
                                    st.caption(f"Service Version: {item.get('version', 'Unknown')}")
                                    st.error(f"Risk Level: {item['risk']}")
                                    st.write(f"Reason: {item['reason']}")

                                    st.info(
                                        f"Recommendation: {item['recommendation']}"
                                    )

                        else:
                            st.success("No known risk indicators detected.")

                    else:
                        st.error(f"Scan failed: {response.text}")

            except ValueError:
                st.error("Please enter a valid IP address.")

            except requests.exceptions.RequestException as e:
                st.error(f"Agent connection error: {e}")

        st.caption(
            "Only scan systems you own or have permission to test."
        )


# ==========================================
# TAB 2: WIRESHARK / TSHARK
# ==========================================

with tab2:
    st.subheader("📦 Network Traffic Capture")

    st.write(
        "Capture real network packets using Wireshark TShark."
    )

    col1, col2 = st.columns(2)
    if os.name == "nt":
        tshark_path = r"C:\Program Files\Wireshark\tshark.exe"
    else:
        tshark_path = shutil.which("tshark")

    interfaces = []

    if tshark_path:
        try:
            result = subprocess.run(
                [tshark_path, "-D"],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    parts = line.split(".", 1)

                    if len(parts) == 2 and parts[0].strip().isdigit():
                        interface_id = int(parts[0].strip())
                        interface_name = parts[1].strip()
                        interfaces.append((interface_id, interface_name))

        except Exception as e:
            st.warning(f"TShark error: {e}")
    else:
        st.warning("TShark is not available in this environment.")

    with col1:

        if interfaces:
            interface_choice = st.selectbox(
                "Select Network Interface",
                interfaces,
                format_func=lambda item: "Wi-Fi" if "wi-fi" in item[1].lower() or "wireless" in item[1].lower() else
                item[1].split(" (")[0],
            )

            interface = interface_choice[0]
        else:
            st.info("No network interfaces available.")
            interface = None



    with col2:

        packet_count = st.number_input(
            "Number of Packets",
            min_value=1,
            max_value=100,
            value=20,
            step=1
        )

    if st.button(
            "📡 Capture Network Packets",
            key="capture_packets_button",
        disabled=not interfaces
    ):

        with st.spinner("Capturing packets..."):

            results = capture_traffic(
                int(interface),
                int(packet_count)
            )

        if isinstance(results, dict) and "error" in results:

            st.error(results["error"])

        elif results:

            st.success(f"Captured {len(results)} packets.")

            st.dataframe(
                results,
                use_container_width=True
            )

            # Basic Statistics
            total_packets = len(results)

            total_bytes = sum(
                int(packet["length"])
                for packet in results
                if str(packet["length"]).isdigit()
            )

            col1, col2 = st.columns(2)

            with col1:
                st.metric("Total Packets", total_packets)

            with col2:
                st.metric("Total Data (Bytes)", total_bytes)

            # Protocol Distribution
            protocol_counts = {}

            for packet in results:
                protocol = packet["protocol"].split(".")[-1].upper()
                protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1

            st.subheader("Protocol Distribution")

            st.bar_chart(
                protocol_counts,
                x_label="Protocol",
                y_label="Packet Count"
            )
            destination_counts = {}

            for packet in results:
                destination = packet["destination"]

                if destination != "N/A":
                    destination_counts[destination] = destination_counts.get(destination, 0) + 1

            st.subheader("Top Talkers - Destination IPs")

            st.bar_chart(
                destination_counts,
                x_label="Destination IP",
                y_label="Packets Received"
            )
            # Top Talkers
            source_counts = {}

            for packet in results:
                source = packet["source"]

                if source != "N/A":
                    source_counts[source] = source_counts.get(source, 0) + 1

            st.subheader("Top Talkers - Source IPs")

            st.bar_chart(
                source_counts,
                x_label="Source IP",
                y_label="Packets Sent"
            )

        else:
            st.warning("No packets were returned.")

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
