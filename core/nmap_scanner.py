import subprocess
import xml.etree.ElementTree as ET


def scan_target(target, options=None, custom_options=None):

    allowed_options = {
        "-sS", "-sT", "-sV", "-sC",
        "-O", "-A", "-Pn", "-sn",
        "-sU", "-F", "-T2", "-T3", "-T4"
    }

    if not target or not target.strip():
        return {"error": "Target is required"}

    options = options or []
    custom_options = custom_options or []

    if any(option not in allowed_options for option in options):
        return {"error": "Invalid scan option"}

    if any(
        not option.startswith("-")
        or option.startswith("--")
        or any(char in option for char in ";&|`$<>")
        for option in custom_options
    ):
        return {"error": "Invalid custom option"}

    command = [
        "nmap",
        *options,
        *custom_options,
        "-oX", "-",
        target.strip()
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=180
        )

        if result.returncode != 0:
            return {"error": result.stderr}

        root = ET.fromstring(result.stdout)

        scan_results = []

        for host in root.findall("host"):
            for port in host.findall(".//port"):
                state = port.find("state")
                service = port.find("service")

                scan_results.append({
                    "port": port.get("portid"),
                    "protocol": port.get("protocol"),
                    "state": state.get("state") if state is not None else "unknown",
                    "service": service.get("name") if service is not None else "unknown",
                    "version": service.get("version", "") if service is not None else ""
                })

        return scan_results

    except subprocess.TimeoutExpired:
        return {"error": "Scan timed out"}

    except Exception as e:
        return {"error": str(e)}
