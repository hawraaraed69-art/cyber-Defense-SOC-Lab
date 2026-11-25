import ipaddress
import os
import re
import secrets
import shutil
import subprocess
import sys

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from core.traffic_analyzer import capture_traffic, TSHARK_PATH


# =========================================================
# 1. APPLICATION CONFIGURATION
# =========================================================

app = FastAPI(title="Cyber Defense Local Agent")

ALLOWED_NMAP_OPTIONS = {
    "-sS", "-sT", "-sV", "-sC",
    "-O", "-A", "-Pn", "-sn",
    "-sU", "-F", "-T2", "-T3", "-T4",
}

NMAP_TIMEOUT = 120
CAPTURE_TIMEOUT = 150
MAX_CAPTURE_PACKETS = 100

security = HTTPBearer(auto_error=False)


# =========================================================
# 2. STUDENT CONFIGURATION
# =========================================================

if getattr(sys, "frozen", False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

load_dotenv(os.path.join(BASE_DIR, ".env"), override=False)

API_TOKEN = os.getenv("SOC_AGENT_TOKEN", "").strip()
STUDENT_ID = os.getenv("STUDENT_ID", "").strip()


# =========================================================
# 3. AUTHENTICATION
# =========================================================

def verify_token(
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    """التحقق من رمز الجهاز إذا كان SOC_AGENT_TOKEN محدداً في .env."""
    if not API_TOKEN:
        return True

    if (
        credentials is None
        or not secrets.compare_digest(credentials.credentials, API_TOKEN)
    ):
        raise HTTPException(status_code=401, detail="Unauthorized")

    return True


# =========================================================
# 4. INPUT VALIDATION
# =========================================================

def validate_target(target):
    """السماح بفحص عناوين IP الخاصة فقط."""
    try:
        ip = ipaddress.ip_address(str(target).strip())
    except ValueError:
        raise ValueError("Invalid IP address")

    if not ip.is_private:
        raise PermissionError("Only private IP addresses are allowed")

    return str(ip)


def validate_nmap_options(options):
    """التحقق من خيارات Nmap ومنع الخيارات المتعارضة."""
    if not isinstance(options, list) or not options:
        options = ["-sV"]

    if any(not isinstance(option, str) for option in options):
        raise ValueError("Nmap options must be a list of strings")

    invalid_options = set(options) - ALLOWED_NMAP_OPTIONS
    if invalid_options:
        raise ValueError(
            "Invalid Nmap options: " + ", ".join(sorted(invalid_options))
        )

    scan_types = set(options) & {"-sS", "-sT", "-sU"}
    if len(scan_types) > 1:
        raise ValueError("Choose only one scan type: -sS, -sT, or -sU")

    timing_options = set(options) & {"-T2", "-T3", "-T4"}
    if len(timing_options) > 1:
        raise ValueError("Choose only one timing option: -T2, -T3, or -T4")

    if "-sn" in options:
        incompatible = {
            "-sS", "-sT", "-sU", "-sV", "-sC", "-O", "-A", "-F"
        }
        if set(options) & incompatible:
            raise ValueError(
                "-sn cannot be combined with port-scanning options"
            )

    return options


# =========================================================
# 5. NMAP SCANNING
# =========================================================

def run_nmap_scan(target, options=None):
    """تنفيذ Nmap محلياً على جهاز الطالب وإرجاع نتيجة منظمة."""
    target_ip = validate_target(target)
    selected_options = validate_nmap_options(options or ["-sV"])

    nmap_path = shutil.which("nmap")
    if not nmap_path:
        raise RuntimeError(
            "Nmap was not found. Install Nmap and make sure it is in PATH."
        )

    try:
        result = subprocess.run(
            [nmap_path, *selected_options, target_ip],
            capture_output=True,
            text=True,
            timeout=NMAP_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise TimeoutError(
            f"Nmap scan exceeded the {NMAP_TIMEOUT}-second time limit."
        )

    output = result.stdout or ""
    error_output = result.stderr or ""

    if result.returncode != 0:
        raise RuntimeError(
            error_output.strip()
            or output.strip()
            or f"Nmap exited with code {result.returncode}"
        )

    return {
        "target": target_ip,
        "options": selected_options,
        "output": output,
        "error": "",
        "return_code": result.returncode,
    }


@app.post("/scan")
def scan_endpoint(
    target: str,
    options: list[str] = Query(default=["-sV"]),
    authorized: bool = Depends(verify_token),
):
    """واجهة محلية لفحص Nmap."""
    try:
        return run_nmap_scan(target, options)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))
    except PermissionError as error:
        raise HTTPException(status_code=403, detail=str(error))
    except TimeoutError as error:
        raise HTTPException(status_code=408, detail=str(error))
    except RuntimeError as error:
        raise HTTPException(status_code=500, detail=str(error))


# =========================================================
# 6. TSHARK NETWORK INTERFACES
# =========================================================

def get_network_interfaces():
    """جلب واجهات الالتقاط الفعلية من TShark."""
    if not TSHARK_PATH or not os.path.isfile(TSHARK_PATH):
        raise RuntimeError(
            "TShark was not found. Install Wireshark with TShark."
        )

    try:
        result = subprocess.run(
            [TSHARK_PATH, "-D"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise TimeoutError("Listing network interfaces timed out.")

    if result.returncode != 0:
        raise RuntimeError(
            (result.stderr or "").strip()
            or "TShark could not list network interfaces."
        )

    interfaces = []

    for line in result.stdout.splitlines():
        match = re.match(r"^\s*(\d+)\.\s+(.+?)\s*$", line)
        if match:
            interfaces.append({
                "id": match.group(1),
                "name": match.group(2).strip(),
            })

    return interfaces


def resolve_capture_interface(interface):
    """مطابقة اختيار الطالب مع رقم الواجهة الذي يتطلبه TShark."""
    if interface is None:
        raise ValueError("Select a network interface first.")

    selected = str(interface).strip()
    if not selected:
        raise ValueError("Network interface cannot be empty.")

    interfaces = get_network_interfaces()

    for item in interfaces:
        if selected == item["id"]:
            return item["id"]

    for item in interfaces:
        if selected.casefold() == item["name"].casefold():
            return item["id"]

    for item in interfaces:
        if selected.casefold() in item["name"].casefold():
            return item["id"]

    raise ValueError(f"Capture interface not found: {selected}")


@app.get("/interfaces")
def interfaces_endpoint(authorized: bool = Depends(verify_token)):
    """إرجاع كروت الشبكة المتاحة لالتقاط الحزم."""
    try:
        return {"interfaces": get_network_interfaces()}
    except TimeoutError as error:
        raise HTTPException(status_code=408, detail=str(error))
    except RuntimeError as error:
        raise HTTPException(status_code=500, detail=str(error))


# =========================================================
# 7. PACKET CAPTURE
# =========================================================

def run_packet_capture(interface, count=20):
    """التقاط عدد محدد من الحزم باستخدام أداة المشروع."""
    try:
        packet_count = int(count)
    except (TypeError, ValueError):
        raise ValueError("Packet count must be an integer.")

    if packet_count < 1 or packet_count > MAX_CAPTURE_PACKETS:
        raise ValueError(
            f"Packet count must be between 1 and {MAX_CAPTURE_PACKETS}."
        )

    interface_number = resolve_capture_interface(interface)

    try:
        packets = capture_traffic(interface_number, packet_count)
    except Exception as error:
        raise RuntimeError(f"Packet capture failed: {error}")

    if isinstance(packets, dict) and packets.get("error"):
        raise RuntimeError(str(packets["error"]))

    if packets is None:
        packets = []

    if not isinstance(packets, list):
        raise RuntimeError("Traffic analyzer returned an unexpected format.")

    return {
        "interface": interface_number,
        "packet_count": len(packets),
        "packets": packets,
    }


@app.post("/capture")
def capture_endpoint(
    interface: str,
    count: int = 20,
    authorized: bool = Depends(verify_token),
):
    """واجهة محلية لالتقاط الحزم."""
    try:
        return run_packet_capture(interface, count)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))
    except TimeoutError as error:
        raise HTTPException(status_code=408, detail=str(error))
    except RuntimeError as error:
        raise HTTPException(status_code=500, detail=str(error))


# =========================================================
# 8. LOCAL AGENT HEALTH
# =========================================================

@app.get("/health")
def health():
    return {
        "status": "online",
        "agent": "Cyber Defense SOC Lab",
        "student_configured": bool(STUDENT_ID and API_TOKEN),
        "nmap_available": bool(shutil.which("nmap")),
        "tshark_available": bool(TSHARK_PATH and os.path.isfile(TSHARK_PATH)),
    }


@app.get("/protected")
def protected_route(authorized: bool = Depends(verify_token)):
    return {"message": "Authenticated successfully"}


# =========================================================
# 9. RUN LOCAL AGENT
# =========================================================

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        app,
        host="127.0.0.1",
        port=8000,
        log_level="info",
    )
