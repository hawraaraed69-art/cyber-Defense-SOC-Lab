import subprocess
import json
import os
import shutil


# تحديد مسار TShark حسب نظام التشغيل
if os.name == "nt":
    WINDOWS_TSHARK = r"C:\Program Files\Wireshark\tshark.exe"

    TSHARK_PATH = (
        WINDOWS_TSHARK
        if os.path.isfile(WINDOWS_TSHARK)
        else shutil.which("tshark")
    )
else:
    TSHARK_PATH = shutil.which("tshark")


# الحد الأعلى لعدد الحزم المسموح بالتقاطها
MAX_CAPTURE_PACKETS = 100


def get_field(layer, field, default="N/A"):
    """استخراج قيمة الحقل من بيانات الحزمة."""

    value = layer.get(field, default)

    if isinstance(value, list):
        return str(value[0]) if value else default

    if isinstance(value, dict):
        return str(value)

    return str(value)


def capture_traffic(interface, count=20):
    """التقاط وتحليل حزم الشبكة باستخدام TShark."""

    if not TSHARK_PATH or not os.path.isfile(TSHARK_PATH):
        return {"error": "TShark is not installed or its path is invalid."}

    if interface is None or not str(interface).strip():
        return {"error": "A network interface must be selected."}

    try:
        count = int(count)
    except (TypeError, ValueError):
        return {"error": "Packet count must be an integer."}

    if count < 1 or count > MAX_CAPTURE_PACKETS:
        return {
            "error": f"Packet count must be between 1 and {MAX_CAPTURE_PACKETS}."
        }

    command = [
        TSHARK_PATH,
        "-i", str(interface),
        "-c", str(count),
        "-T", "json"
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=120,
            check=False
        )

        if result.returncode != 0:
            return {
                "error": result.stderr.strip()
                or "TShark capture failed."
            }

        try:
            packets = json.loads(result.stdout)
        except json.JSONDecodeError:
            return {"error": "Could not decode TShark JSON output."}

        if not isinstance(packets, list):
            return {"error": "Unexpected TShark output format."}

        traffic = []

        for packet in packets:
            layers = (
                packet.get("_source", {})
                .get("layers", {})
            )

            tcp = layers.get("tcp", {})
            udp = layers.get("udp", {})
            frame = layers.get("frame", {})

            ip_layer = layers.get("ip", {})
            ipv6_layer = layers.get("ipv6", {})

            source = (
                get_field(ip_layer, "ip.src")
                if ip_layer
                else get_field(ipv6_layer, "ipv6.src")
            )

            destination = (
                get_field(ip_layer, "ip.dst")
                if ip_layer
                else get_field(ipv6_layer, "ipv6.dst")
            )

            source_port = (
                get_field(tcp, "tcp.srcport")
                if tcp
                else get_field(udp, "udp.srcport")
            )

            destination_port = (
                get_field(tcp, "tcp.dstport")
                if tcp
                else get_field(udp, "udp.dstport")
            )

            traffic.append({
                "source": source,
                "destination": destination,
                "source_port": source_port,
                "destination_port": destination_port,
                "protocol": get_field(frame, "frame.protocols"),
                "length": get_field(frame, "frame.len"),
                "timestamp": get_field(frame, "frame.time")
            })

        return traffic

    except subprocess.TimeoutExpired:
        return {"error": "Packet capture timed out after 120 seconds."}

    except Exception as error:
        return {"error": str(error)}
