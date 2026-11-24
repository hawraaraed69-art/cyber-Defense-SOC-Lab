import io
import ipaddress
import os
import re
from datetime import datetime, timezone

import requests
import streamlit as st
from dotenv import load_dotenv
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    Preformatted,
)

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
# 2. CONFIGURATION
# =========================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(BASE_DIR, ".env"), override=False)

# Cloudflare Worker URL الخاص بالمشروع
RELAY_URL = os.getenv(
    "RELAY_URL",
    "https://solitary-hall-00cf.hawraaraed69.workers.dev",
).rstrip("/")

# APP_SECRET يوضع في Streamlit Cloud Secrets، ولا يوضع في GitHub
try:
    APP_SECRET = st.secrets.get("APP_SECRET", os.getenv("APP_SECRET", ""))
except Exception:
    APP_SECRET = os.getenv("APP_SECRET", "")

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
    "student_token": "",
    "last_scan": None,
    "last_capture": [],
    "last_banner": None,
    "network_interfaces": [],
    "last_risk": None,
    "last_findings": [],
}

for state_key, default_value in DEFAULT_STATE.items():
    if state_key not in st.session_state:
        st.session_state[state_key] = default_value


# =========================================================
# 4. RELAY COMMUNICATION
# =========================================================

def send_relay_command(student_id, student_token, action, payload=None, timeout=150):
    """إرسال أمر إلى Relay وإرجاع بيانات Local Agent بعد التحقق من الأخطاء."""

    if not APP_SECRET:
        raise RuntimeError("APP_SECRET is missing from Streamlit Secrets.")

    if not student_id or not student_token:
        raise RuntimeError("Student ID and Student Token are required.")

    response = requests.post(
        f"{RELAY_URL}/command",
        json={
            "student_id": student_id,
            "student_token": student_token,
            "action": action,
            "payload": payload or {},
        },
        headers={"Authorization": f"Bearer {APP_SECRET}"},
        timeout=timeout,
    )

    try:
        result = response.json()
    except ValueError:
        response.raise_for_status()
        raise RuntimeError("Relay returned an invalid response.")

    if response.status_code >= 400:
        message = result.get("error") or result.get("detail") or response.text
        raise RuntimeError(f"Relay HTTP {response.status_code}: {message}")

    if result.get("error"):
        raise RuntimeError(result["error"])

    data = result.get("data")
    if not isinstance(data, dict):
        raise RuntimeError("The Agent returned an unexpected response format.")

    if data.get("error"):
        raise RuntimeError(data["error"])

    return data


def require_login():
    """إرجاع بيانات الطالب المسجل دخوله أو إيقاف تنفيذ الوظيفة."""

    if not st.session_state.authenticated:
        st.warning("Please sign in with your student credentials first.")
        return None

    return (
        st.session_state.student_id,
        st.session_state.student_token,
    )


# =========================================================
# 5. VALIDATION AND REPORT HELPERS
# =========================================================

def validate_target_ip(value):
    """قبول عنوان IP صحيح فقط؛ Local Agent يطبق نطاق الفحص المسموح."""

    try:
        return str(ipaddress.ip_address(value.strip()))
    except (ValueError, AttributeError):
        raise ValueError("Enter a valid IPv4 or IPv6 address.")


def validate_nmap_options(options):
    errors = []

    scan_types = {"-sS", "-sT", "-sU"}
    selected_scan_types = scan_types.intersection(options)

    if len(selected_scan_types) > 1:
        errors.append("Select only one scan technique: -sS, -sT, or -sU.")

    if "-sn" in options:
        port_scan_options = {
            "-sS", "-sT", "-sU", "-sV", "-sC", "-O", "-A", "-F"
        }
        if port_scan_options.intersection(options):
            errors.append("-sn is a host-discovery scan and cannot be combined with port-scan options.")

    timing_options = {"-T2", "-T3", "-T4"}
    if len(timing_options.intersection(options)) > 1:
        errors.append("Select only one timing option: -T2, -T3, or -T4.")

    return errors


def build_pdf_report():
    """إنشاء تقرير PDF من آخر نتائج محفوظة في جلسة الطالب."""

    buffer = io.BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title="Cyber Defense SOC Lab Report",
        author="Cyber Defense SOC Lab",
    )

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="ReportTitle",
        parent=styles["Title"],
        alignment=TA_CENTER,
        textColor=colors.HexColor("#007C91"),
        spaceAfter=12,
    ))
    styles.add(ParagraphStyle(
        name="SectionHeading",
        parent=styles["Heading2"],
        textColor=colors.HexColor("#007C91"),
        spaceBefore=12,
        spaceAfter=6,
    ))

    story = [
        Paragraph("Cyber Defense SOC Lab", styles["ReportTitle"]),
        Paragraph("Network Security Assessment Report", styles["Heading2"]),
        Spacer(1, 6),
        Paragraph(
            f"Student ID: {st.session_state.student_id}",
            styles["BodyText"],
        ),
        Paragraph(
            f"Generated: {datetime.now(timezone.utc).astimezone().strftime('%Y-%m-%d %H:%M:%S %Z')}",
            styles["BodyText"],
        ),
        Spacer(1, 12),
    ]

    scan = st.session_state.last_scan
    if scan:
        story.append(Paragraph("Nmap Scan", styles["SectionHeading"]))
        story.append(Paragraph(
            f"Target: {scan.get('target', 'N/A')} | "
            f"Options: {', '.join(scan.get('options', []))}",
            styles["BodyText"],
        ))
        risk = st.session_state.last_risk or {}
        story.append(Paragraph(
            f"Risk indicator score: {risk.get('score', 'N/A')}/100 | "
            f"Level: {risk.get('level', 'N/A')}",
            styles["BodyText"],
        ))
        story.append(Spacer(1, 6))
        story.append(Preformatted(
            scan.get("output", "No scan output."),
            styles["Code"],
        ))
    else:
        story.append(Paragraph(
            "No Nmap scan has been performed in this session.",
            styles["BodyText"],
        ))

    findings = st.session_state.last_findings
    if findings:
        story.append(Paragraph("Risk Findings", styles["SectionHeading"]))
        table_data = [["Port", "Service", "Risk", "Reason"]]
        for item in findings:
            table_data.append([
                str(item.get("port", "")),
                str(item.get("service", "")),
                str(item.get("risk", "")),
                str(item.get("reason", "")),
            ])
        findings_table = Table(
            table_data,
            repeatRows=1,
            colWidths=[18 * mm, 30 * mm, 22 * mm, 95 * mm],
        )
        findings_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#DCEFF2")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#102A35")),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(findings_table)

    story.append(Paragraph("Network Traffic Capture", styles["SectionHeading"]))
    packets = st.session_state.last_capture
    if packets:
        story.append(Paragraph(
            f"Packets captured: {len(packets)}",
            styles["BodyText"],
        ))
        packet_rows = [["No.", "Source", "Destination", "Protocol", "Length"]]
        for index, packet in enumerate(packets, start=1):
            packet_rows.append([
                str(index),
                str(packet.get("source", packet.get("src", ""))),
                str(packet.get("destination", packet.get("dst", ""))),
                str(packet.get("protocol", packet.get("proto", ""))),
                str(packet.get("length", "")),
            ])
        packet_table = Table(
            packet_rows,
            repeatRows=1,
            colWidths=[12 * mm, 38 * mm, 38 * mm, 35 * mm, 22 * mm],
        )
        packet_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#DCEFF2")),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(packet_table)
    else:
        story.append(Paragraph(
            "No traffic capture has been performed in this session.",
            styles["BodyText"],
        ))

    banner = st.session_state.last_banner
    story.append(Paragraph("Banner Grabbing", styles["SectionHeading"]))
    if banner:
        story.append(Paragraph(
            f"Target: {banner.get('target', 'N/A')} | "
            f"Port: {banner.get('port', 'N/A')}",
            styles["BodyText"],
        ))
        story.append(Preformatted(
            str(banner.get("banner", "No banner returned.")),
            styles["Code"],
        ))
    else:
        story.append(Paragraph(
            "No banner-grabbing result has been recorded.",
            styles["BodyText"],
        ))

    story.append(Spacer(1, 16))
    story.append(Paragraph(
        "Educational report. Findings are indicators for review and do not, by themselves, prove exploitation or compromise.",
        styles["Italic"],
    ))

    document.build(story)
    return buffer.getvalue()


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
        st.success("STUDENT AGENT: AUTHENTICATED")
        st.caption(f"Student: {st.session_state.student_id}")
        if st.button("Sign out", key="sign_out_button"):
            for key, value in DEFAULT_STATE.items():
                st.session_state[key] = value
            st.rerun()
    else:
        st.warning("STUDENT AGENT: NOT CONNECTED")

    st.markdown("---")
    st.markdown("**Target Environment**")
    st.info("Authorized Security Lab")
    st.markdown("**Version**")
    st.write("3.0.0 | SOC Edition")
    st.markdown("---")
    st.caption("Cyber Defense Operations Lab")


# =========================================================
# 8. MAIN HEADER AND STUDENT LOGIN
# =========================================================

st.markdown(
    '<p class="soc-title">🌐 ENTERPRISE CYBERSECURITY OPERATIONS LAB</p>',
    unsafe_allow_html=True,
)
st.caption("Network Reconnaissance | Traffic Analysis | Security Monitoring")
st.markdown("---")

if not st.session_state.authenticated:
    st.subheader("🔐 Student Agent Login")
    st.write(
        "Enter the Student ID and Student Token assigned to you. "
        "The local agent must be running on your computer."
    )

    with st.form("student_login_form"):
        login_student_id = st.text_input("Student ID", max_chars=32)
        login_student_token = st.text_input(
            "Student Token",
            type="password",
            max_chars=128,
        )
        login_submitted = st.form_submit_button("Connect to My Agent")

    if login_submitted:
        if not APP_SECRET:
            st.error("The application administrator has not configured APP_SECRET.")
        elif not login_student_id.strip() or not login_student_token.strip():
            st.error("Enter both Student ID and Student Token.")
        else:
            try:
                with st.spinner("Authenticating with your local agent..."):
                    login_data = send_relay_command(
                        login_student_id.strip(),
                        login_student_token.strip(),
                        "interfaces",
                        {},
                        timeout=30,
                    )

                interfaces = login_data.get("interfaces", [])
                st.session_state.authenticated = True
                st.session_state.student_id = login_student_id.strip()
                st.session_state.student_token = login_student_token.strip()
                st.session_state.network_interfaces = interfaces
                st.success("Authentication successful. Your agent is connected.")
                st.rerun()

            except Exception as error:
                st.error(f"Login failed: {error}")

    st.info(
        "Each student must use their own assigned ID and token. "
        "Do not share your token with another student."
    )
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
        '<div class="metric-value">READY</div>'
        '<div>Authenticated session</div></div>',
        unsafe_allow_html=True,
    )

st.markdown("---")


# =========================================================
# 10. MAIN TABS
# =========================================================

tab1, tab2, tab3, tab4 = st.tabs([
    "🔍 Nmap Reconnaissance",
    "📦 Wireshark Traffic",
    "🧾 Banner Grabbing",
    "📄 PDF Reports",
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
        help="Some scan types may require Nmap/Npcap permissions on the student computer.",
    )

    if st.button("🚀 Start Nmap Scan", key="nmap_scan_button"):
        try:
            target = validate_target_ip(target_ip)
            validation_errors = validate_nmap_options(selected_options)

            if validation_errors:
                for message in validation_errors:
                    st.error(message)
            else:
                with st.spinner("Running Nmap on your connected computer..."):
                    results = send_relay_command(
                        st.session_state.student_id,
                        st.session_state.student_token,
                        "scan",
                        {
                            "target": target,
                            "options": selected_options or ["-sV"],
                        },
                        timeout=190,
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
                        "options": selected_options or ["-sV"],
                        "output": output,
                        "timestamp": datetime.now().astimezone().isoformat(),
                    }
                    st.session_state.last_findings = findings
                    st.session_state.last_risk = risk

                    st.success("Nmap scan completed.")
                    st.code(output, language="text")

                    st.subheader("Security Risk Assessment")
                    st.metric("Risk Indicator Score", f"{risk['score']}/100")
                    st.caption(
                        "This score is based on predefined indicators. "
                        "It is not proof of a vulnerability or compromise."
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
    st.write("Capture real packets through TShark on your connected computer.")

    if st.button("🔄 Refresh Network Interfaces", key="refresh_interfaces"):
        try:
            with st.spinner("Loading interfaces from your computer..."):
                data = send_relay_command(
                    st.session_state.student_id,
                    st.session_state.student_token,
                    "interfaces",
                    {},
                    timeout=30,
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
                    data = send_relay_command(
                        st.session_state.student_id,
                        st.session_state.student_token,
                        "capture",
                        {
                            "interface": selected_interface.get("id"),
                            "count": int(packet_count),
                        },
                        timeout=150,
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
# TAB 3: BANNER GRABBING
# =========================================================

with tab3:
    st.subheader("🧾 Banner Grabbing")
    st.write("Retrieve service response information from an authorized target.")

    banner_ip = st.text_input(
        "Target IP",
        value="127.0.0.1",
        key="banner_target_ip",
    )
    banner_port = st.number_input(
        "Target Port",
        min_value=1,
        max_value=65535,
        value=80,
        step=1,
        key="banner_target_port",
    )

    if st.button("🔎 Grab Service Banner", key="banner_grab_button"):
        try:
            target = validate_target_ip(banner_ip)

            with st.spinner("Requesting banner from your connected computer..."):
                data = send_relay_command(
                    st.session_state.student_id,
                    st.session_state.student_token,
                    "banner",
                    {
                        "target": target,
                        "port": int(banner_port),
                    },
                    timeout=20,
                )

            banner_text = data.get("banner", data.get("output", ""))
            st.session_state.last_banner = {
                "target": target,
                "port": int(banner_port),
                "banner": banner_text,
            }

            if banner_text:
                st.success("Service response received.")
                server_value = data.get("server")
                if server_value:
                    st.write("**Detected Server:**", server_value)
                st.code(banner_text, language="text")
            else:
                st.info("The target did not disclose a banner.")

        except ValueError as error:
            st.error(str(error))
        except Exception as error:
            st.error(f"Banner grabbing failed: {error}")

    st.caption("Use only on systems you own or have permission to test.")


# =========================================================
# TAB 4: PDF REPORTS
# =========================================================

with tab4:
    st.subheader("📄 Automated PDF Reports")
    st.write(
        "Generate a report using the Nmap, traffic capture, and banner results "
        "saved in your current session."
    )

    st.caption(
        "The report includes only results collected in this student session. "
        "It does not include student tokens."
    )

    has_results = any([
        st.session_state.last_scan,
        st.session_state.last_capture,
        st.session_state.last_banner,
    ])

    if has_results:
        try:
            pdf_bytes = build_pdf_report()
            st.download_button(
                label="⬇️ Download Security Assessment PDF",
                data=pdf_bytes,
                file_name=f"CyberDefense_Report_{st.session_state.student_id}.pdf",
                mime="application/pdf",
                key="download_pdf_report",
            )
        except Exception as error:
            st.error(f"PDF generation failed: {error}")
    else:
        st.info("Run a scan, capture traffic, or grab a banner to create a report.")


# =========================================================
# 11. FOOTER
# =========================================================

st.markdown("---")
st.caption(
    "Cyber Defense SOC Lab | Educational and Authorized Security Testing"
)
