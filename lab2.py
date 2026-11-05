import streamlit as st
import socket

from core.nmap_scanner import scan_target
from core.traffic_analyzer import capture_traffic


# ==========================================
# 1. PAGE CONFIGURATION
# ==========================================

st.set_page_config(
    page_title="Cyber Defense SOC Lab",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)


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
        value="127.0.0.1"
    )

    selected_options = st.multiselect(
        "Nmap Scan Options",
        [
            "-sS", "-sT", "-sV", "-sC",
            "-O", "-A", "-Pn", "-sn",
            "-sU", "-F", "-T2", "-T3", "-T4"
        ],
        default=["-sV"]
    )

    if st.button("🚀 Start Nmap Scan"):

        with st.spinner("Scanning target..."):

            results = scan_target(
                target_ip,
                selected_options
            )

        if isinstance(results, dict) and "error" in results:

            st.error(results["error"])

        elif results:

            st.success("Scan completed successfully!")

            st.dataframe(
                results,
                use_container_width=True
            )

        else:

            st.info("No open ports found or no results returned.")

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

    with col1:

        interface = st.number_input(
            "Network Interface ID",
            min_value=1,
            max_value=100,
            value=4,
            step=1
        )

    with col2:

        packet_count = st.number_input(
            "Number of Packets",
            min_value=1,
            max_value=500,
            value=20,
            step=1
        )

    if st.button("📡 Capture Network Packets"):

        with st.spinner("Capturing packets..."):

            results = capture_traffic(
                interface,
                packet_count
            )

        if isinstance(results, dict) and "error" in results:

            st.error(results["error"])

        elif results:

            st.success(
                f"Captured {len(results)} packets."
            )

            st.dataframe(
                results,
                use_container_width=True
            )

        else:

            st.warning("No packets were returned.")

    st.caption(
        "Captures a fixed number of packets, not continuous live streaming."
    )


# ==========================================
# TAB 3: BANNER GRABBING
# ==========================================

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

    if st.button("🔎 Grab Service Banner"):

        try:

            with socket.create_connection(
                (banner_ip, int(banner_port)),
                timeout=5
            ) as sock:

                sock.settimeout(3)

                request = (
                    "HEAD / HTTP/1.1\r\n"
                    f"Host: {banner_ip}\r\n"
                    "Connection: close\r\n\r\n"
                )

                sock.sendall(request.encode())

                response = sock.recv(4096).decode(
                    errors="replace"
                )

                if response:

                    st.success("Server response received.")

                    st.code(response, language="http")

                else:

                    st.warning(
                        "The server did not return a response."
                    )

        except socket.timeout:

            st.warning("Connection timed out.")

        except OSError as e:

            st.error(f"Connection error: {e}")


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