import subprocess
import json
import os
import shutil

TSHARK_PATH = (
    r"C:\Program Files\Wireshark\tshark.exe"
    if os.name == "nt"
    else shutil.which("tshark")
)




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

            tcp = layers.get("tcp", {})
            udp = layers.get("udp", {})
            frame = layers.get("frame", {})

            traffic.append({
                "source": layers.get("ip", {}).get("ip.src", "N/A"),
                "destination": layers.get("ip", {}).get("ip.dst", "N/A"),
                "source_port": tcp.get("tcp.srcport", udp.get("udp.srcport", "N/A")),
                "destination_port": tcp.get("tcp.dstport", udp.get("udp.dstport", "N/A")),
                "protocol": frame.get("frame.protocols", "N/A"),
                "length": frame.get("frame.len", "N/A"),
                "timestamp": frame.get("frame.time", "N/A")
            })

        return traffic

    except Exception as e:
        return {"error": str(e)}

