from fastapi import FastAPI, HTTPException, Depends,Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import subprocess
import ipaddress
import secrets
import shutil
from core.traffic_analyzer import capture_traffic
import os
from dotenv import load_dotenv

app = FastAPI(title="Cyber Defense Local Agent")
ALLOWED_NMAP_OPTIONS = {
    "-sS", "-sT", "-sV", "-sC",
    "-O", "-A", "-Pn", "-sn",
    "-sU", "-F", "-T2", "-T3", "-T4"
}

# Secret API Token
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), ".env"), override=True)
API_TOKEN = os.getenv("SOC_AGENT_TOKEN")

security = HTTPBearer()


# التحقق من الرمز السري
def verify_token(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    if not secrets.compare_digest(
        credentials.credentials,
        API_TOKEN
    ):
        raise HTTPException(
            status_code=401,
            detail="Unauthorized"
        )


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
    return {
        "message": "Authenticated successfully"
    }


# فحص Nmap

@app.post("/scan")
def scan_network(
    target: str,
    options: list[str] = Query(default= ["-sV"]),
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
            timeout=180)


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


@app.post("/capture")
def capture_network(
            interface: int,
            count: int = 20,
authorized: bool = Depends(verify_token)
    ):
        if interface < 1:
            raise HTTPException(
                status_code=400,
                detail="Invalid interface ID"
            )

        if count < 1 or count > 100:
            raise HTTPException(
                status_code=400,
                detail="Packet count must be between 1 and 100"
            )

        result = capture_traffic(interface, count)

        if isinstance(result, dict) and "error" in result:
            raise HTTPException(
                status_code=500,
                detail=result["error"]
                )

        return {
            "interface": interface,
            "packet_count": len(result),
            "packets": result
        }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
