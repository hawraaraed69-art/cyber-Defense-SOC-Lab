from fastapi import FastAPI, HTTPException, Depends, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import subprocess
import ipaddress
import secrets
import shutil
import os
import websocket
import threading
import json
import uuid
import time
import re
from dotenv import load_dotenv
import sys
# استيراد أداة الالتقاط ومسار TShark
from core.traffic_analyzer import capture_traffic, TSHARK_PATH

app = FastAPI(title="Cyber Defense Local Agent")

ALLOWED_NMAP_OPTIONS = {
    "-sS", "-sT", "-sV", "-sC",
    "-O", "-A", "-Pn", "-sn",
    "-sU", "-F", "-T2", "-T3", "-T4"
}

# قراءة إعدادات الطالب من ملف البيئة



# تحديد مجلد البرنامج سواء اشتغل Python أو EXE
if getattr(sys, "frozen", False):
    base_dir = os.path.dirname(sys.executable)
else:
    base_dir = os.path.dirname(os.path.abspath(__file__))

# قراءة ملف .env الموجود بجانب البرنامج
load_dotenv(os.path.join(base_dir, ".env"))
API_TOKEN = os.getenv("SOC_AGENT_TOKEN")

# عنوان Cloudflare Relay
RELAY_URL = os.getenv(
    "RELAY_URL",
    "wss://solitary-hall-00cf.hawraaraed69.workers.dev/agent"
)

# هوية الطالب
STUDENT_ID = os.getenv("STUDENT_ID", "")

security = HTTPBearer()


# التحقق من رمز المصادقة
def verify_token(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    if not API_TOKEN or not secrets.compare_digest(
        credentials.credentials,
        API_TOKEN
    ):
        raise HTTPException(status_code=401, detail="Unauthorized")


# اختبار تشغيل Agent
@app.get("/health")
def health():
    return {
        "status": "online",
        "agent": "Cyber Defense SOC Lab"
    }


# اختبار الحماية
@app.get("/protected")
def protected_route(
    authorized: bool = Depends(verify_token)
):
    return {"message": "Authenticated successfully"}


# فحص Nmap
@app.post("/scan")
def scan_network(
    target: str,
    options: list[str] = Query(default=["-sV"]),
    authorized: bool = Depends(verify_token)
):
    try:
        ip = ipaddress.ip_address(target)

        if not ip.is_private:
            raise HTTPException(
                status_code=403,
                detail="Only private IP addresses are allowed"
            )

        nmap_path = shutil.which("nmap")

        if not nmap_path:
            raise HTTPException(
                status_code=500,
                detail="Nmap is not installed or not found"
            )

        if not options:
            options = ["-sV"]

        invalid_options = set(options) - ALLOWED_NMAP_OPTIONS

        if invalid_options:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid Nmap options: {invalid_options}"
            )

        scan_types = set(options) & {"-sS", "-sT", "-sU"}

        if len(scan_types) > 1:
            raise HTTPException(
                status_code=400,
                detail="Choose only one scan type"
            )

        result = subprocess.run(
            [nmap_path, *options, str(ip)],
            capture_output=True,
            text=True,
            timeout=180
        )

        return {
            "target": str(ip),
            "output": result.stdout,
            "error": result.stderr
        }

    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="Invalid IP address"
        )

    except subprocess.TimeoutExpired:
        raise HTTPException(
            status_code=408,
            detail="Scan timed out"
        )


# تحويل اسم الواجهة إلى رقم TShark الصحيح
def resolve_capture_interface(interface):
    if not TSHARK_PATH:
        raise RuntimeError("TShark executable was not found")

    if interface is None:
        raise ValueError("No capture interface selected")

    selected = str(interface).strip()

    # جلب قائمة واجهات الالتقاط الحقيقية من TShark
    result = subprocess.run(
        [TSHARK_PATH, "-D"],
        capture_output=True,
        text=True,
        timeout=15
    )

    if result.returncode != 0:
        raise RuntimeError(result.stderr or "Cannot list interfaces")

    # البحث عن الواجهة التي اختارها الطالب
    for line in result.stdout.splitlines():

        match = re.match(r"^\s*(\d+)\.\s+", line)

        if not match:
            continue

        interface_number = match.group(1)

        # قبول الرقم أو الاسم الظاهر أو معرّف NPF
        if (
            selected == interface_number
            or selected.casefold() in line.casefold()
        ):
            return interface_number

    raise ValueError(
        f"Capture interface not found: {selected}"
    )


# التقاط الحزم من واجهة الشبكة
@app.post("/capture")
def capture_network(
    interface: int,
    count: int = 20,
    authorized: bool = Depends(verify_token)
):
    if count < 1 or count > 100:
        raise HTTPException(
            status_code=400,
            detail="Packet count must be between 1 and 100"
        )

    try:
        # تحويل الواجهة إلى رقمها الحقيقي في TShark
        interface_number = resolve_capture_interface(interface)

        result = capture_traffic(interface_number, count)

        if isinstance(result, dict) and "error" in result:
            raise HTTPException(
                status_code=500,
                detail=result["error"]
            )

        return {
            "interface": interface_number,
            "packet_count": len(result),
            "packets": result
        }

    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))


# معالجة الأوامر القادمة من Cloudflare Relay
         # معالجة الأوامر القادمة من Cloudflare Relay
def process_relay_command(data):

    request_id = data.get("id")

    response = {
        "type": "result",
        "id": request_id
    }

    try:
        if data.get("type") != "command" or not request_id:
            raise ValueError("Invalid command")

        action = data.get("action")
        payload = data.get("payload") or {}

        if not isinstance(payload, dict):
            raise ValueError("Invalid command payload")

        # جلب واجهات الشبكة الحقيقية من جهاز الطالب
        if action == "interfaces":

            if not TSHARK_PATH:
                raise RuntimeError("TShark executable was not found")

            result = subprocess.run(
                [TSHARK_PATH, "-D"],
                capture_output=True,
                text=True,
                timeout=15
            )

            if result.returncode != 0:
                raise RuntimeError(
                    result.stderr or "Cannot list network interfaces"
                )

            interfaces = []

            # تحويل قائمة TShark إلى بيانات منظمة
            for line in result.stdout.splitlines():
                match = re.match(r"^\s*(\d+)\.\s+(.+)$", line)

                if match:
                    interfaces.append({
                        "id": match.group(1),
                        "name": match.group(2).strip()
                    })

            response["data"] = {
                "interfaces": interfaces
            }

        # تنفيذ فحص Nmap
        elif action == "scan":

            result = scan_network(
                target=payload.get("target"),
                options=payload.get("options") or ["-sV"],
                authorized=True
            )

            response["data"] = result

        # تنفيذ التقاط Wireshark
        elif action == "capture":

            result = capture_network(
                interface=payload.get("interface"),
                count=payload.get("count", 20),
                authorized=True
            )

            response["data"] = result

        else:
            raise ValueError("Unsupported action")

    except Exception as error:
        response["error"] = str(error)

    return response
            except Exception as e:
              response["error"] = str(e)
             return response  

        if not isinstance(payload, dict):
            raise ValueError("Invalid command payload")

        # تنفيذ فحص Nmap
        if action == "scan":
            result = scan_network(
                target=payload.get("target"),
                options=payload.get("options") or ["-sV"],
                authorized=True
            )

        # تنفيذ التقاط Wireshark
        elif action == "capture":
            result = capture_network(
                interface=payload.get("interface"),
                count=payload.get("count", 20),
                authorized=True
            )

        else:
            raise ValueError("Unsupported action")

        response["data"] = result

    except Exception as error:
        response["error"] = str(error)

    return response


# تشغيل اتصال مستمر مع Cloudflare Relay
def connect_to_relay():

    if not STUDENT_ID or not API_TOKEN:
        print("Relay connection requires STUDENT_ID and SOC_AGENT_TOKEN")
        return

    relay_address = f"{RELAY_URL}?student_id={STUDENT_ID}"

    while True:
        ws = None

        try:
            ws = websocket.create_connection(
                relay_address,
                header=[f"Authorization: Bearer {API_TOKEN}"],
                timeout=None
            )

            print("Connected to Cloudflare Relay")

            while True:
                message = ws.recv()

                if not message:
                    break

                data = json.loads(message)
                response = process_relay_command(data)

                ws.send(json.dumps(response))

        except Exception as error:
            print(f"Relay connection error: {error}")

        finally:
            if ws:
                try:
                    ws.close()
                except Exception:
                    pass

        time.sleep(5)


# تشغيل الاتصال في مسار مستقل عند بدء FastAPI
@app.on_event("startup")
def start_relay_connection():

    relay_thread = threading.Thread(
        target=connect_to_relay,
        daemon=True
    )

    relay_thread.start()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
