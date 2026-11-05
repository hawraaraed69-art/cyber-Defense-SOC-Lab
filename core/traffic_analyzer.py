import subprocess
import json


TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe"


def capture_traffic(interface, count=50):

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
            timeout=120
        )

        if result.returncode != 0:
            return {"error": result.stderr}

        packets = json.loads(result.stdout)
        traffic = []

        for packet in packets:
            layers = packet.get("_source", {}).get("layers", {})

            traffic.append({
                "source": layers.get("ip", {}).get("ip.src", "N/A"),
                "destination": layers.get("ip", {}).get("ip.dst", "N/A"),
                "protocol": layers.get("frame", {}).get("frame.protocols", "N/A"),
                "length": layers.get("frame", {}).get("frame.len", "N/A")
            })

        return traffic

    except Exception as e:
        return {"error": str(e)}
