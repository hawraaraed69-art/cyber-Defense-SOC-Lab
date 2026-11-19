import re


def extract_open_ports(nmap_output):

    open_ports = []

    for line in nmap_output.splitlines():

        match = re.match(
            r"^\s*(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.*))?$",
            line
        )

        if match:
            open_ports.append({
                "port": int(match.group(1)),
                "protocol": match.group(2),
                "service": match.group(3),
                "version": match.group(4) or "Unknown"
            })

    return open_ports
def analyze_risks(open_ports):

    findings = []

    risky_services = {
        21: {
            "risk": "Medium",
            "reason": "FTP may transmit credentials without encryption.",
            "recommendation": "Use secure file transfer such as SFTP."
        },
        23: {
            "risk": "High",
            "reason": "Telnet transmits data without encryption.",
            "recommendation": "Disable Telnet and use SSH."
        },
        80: {
            "risk": "Low",
            "reason": "HTTP traffic is not encrypted.",
            "recommendation": "Use HTTPS with a valid TLS certificate."
        },
        445: {
            "risk": "High",
            "reason": "SMB exposure may increase network attack surface.",
            "recommendation": "Restrict SMB access to trusted networks."
        },
        3389: {
            "risk": "High",
            "reason": "Exposed Remote Desktop may increase attack risk.",
            "recommendation": "Restrict RDP access and enable strong authentication."
        }
    }

    for item in open_ports:

        port = item["port"]

        if port in risky_services:

            finding = {
                "port": port,
                "service": item["service"],"version": item.get("version", "Unknown"),
                **risky_services[port]
            }

            findings.append(finding)

    return findings
def calculate_risk(findings):

    if not findings:
        return {
            "score": 0,
            "level": "No Indicators"
        }

    weights = {
        "High": 25,
        "Medium": 15,
        "Low": 5
    }

    score = sum(
        weights.get(item["risk"], 0)
        for item in findings
    )

    score = min(score, 100)

    if score >= 60:
        level = "High"
    elif score >= 25:
        level = "Medium"
    else:
        level = "Low"

    return {
        "score": score,
        "level": level
    }