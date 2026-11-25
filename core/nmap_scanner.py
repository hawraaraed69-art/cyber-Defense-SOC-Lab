import subprocess
import xml.etree.ElementTree as ET
import ipaddress
import shutil


# خيارات Nmap المسموح باستخدامها
ALLOWED_OPTIONS = {
    "-sS", "-sT", "-sV", "-sC",
    "-O", "-A", "-Pn", "-sn",
    "-sU", "-F", "-T2", "-T3", "-T4"
}

# خيارات إضافية محددة وآمنة
ALLOWED_CUSTOM_OPTIONS = {
    "--open",
    "--reason",
    "--traceroute",
    "-n"
}


def validate_target(target):
    """التحقق من أن الهدف عنوان IP خاص ومسموح."""

    try:
        ip = ipaddress.ip_address(target.strip())

        if not ip.is_private:
            return False

        return True

    except ValueError:
        return False


def scan_target(target, options=None, custom_options=None):

    # التحقق من وجود الهدف وصحته
    if not isinstance(target, str) or not target.strip():
        return {"error": "Target is required"}

    target = target.strip()

    if not validate_target(target):
        return {"error": "Only valid private IP addresses are allowed"}

    options = options or []
    custom_options = custom_options or []

    # التأكد من أن الخيارات قوائم
    if not isinstance(options, list) or not isinstance(custom_options, list):
        return {"error": "Options must be lists"}

    # التحقق من خيارات Nmap الأساسية
    if any(option not in ALLOWED_OPTIONS for option in options):
        return {"error": "Invalid scan option"}

    # التحقق من الخيارات الإضافية
    if any(option not in ALLOWED_CUSTOM_OPTIONS for option in custom_options):
        return {"error": "Invalid custom option"}

    # التأكد من وجود Nmap في الجهاز
    nmap_path = shutil.which("nmap")

    if not nmap_path:
        return {"error": "Nmap is not installed or not found in PATH"}

    # منع الجمع بين خيارات الفحص المتعارضة
    scan_types = {"-sS", "-sT", "-sU"}
    selected_scan_types = scan_types.intersection(options)

    if len(selected_scan_types) > 1:
        return {"error": "Conflicting scan types"}

    # بناء أمر الفحص
    command = [
        nmap_path,
        *options,
        *custom_options,
        "-oX", "-",
        target
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=180
        )

        if result.returncode != 0:
            return {
                "error": result.stderr.strip() or "Nmap scan failed"
            }

        # تحويل نتائج XML إلى بيانات Python
        root = ET.fromstring(result.stdout)

        scan_results = []

        for host in root.findall("host"):

            for port in host.findall(".//port"):

                state = port.find("state")
                service = port.find("service")

                scan_results.append({
                    "port": port.get("portid"),
                    "protocol": port.get("protocol"),
                    "state": (
                        state.get("state")
                        if state is not None else "unknown"
                    ),
                    "service": (
                        service.get("name")
                        if service is not None else "unknown"
                    ),
                    "version": (
                        service.get("version", "")
                        if service is not None else ""
                    )
                })

        return scan_results

    except subprocess.TimeoutExpired:
        return {"error": "Scan timed out"}

    except ET.ParseError:
        return {"error": "Failed to parse Nmap XML output"}

    except Exception as e:
        return {"error": str(e)}
