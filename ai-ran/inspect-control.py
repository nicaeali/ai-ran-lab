#!/usr/bin/env python3
"""Decode captured E2AP/E42 and nested E2SM-RC using the pinned runtime codecs."""

from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET

from scapy.all import IP, PcapReader
from scapy.layers.sctp import SCTP, SCTPChunkData
from scapy.packet import NoPayload


BIN = Path("/opt/ai-ran/bin")


def messages(path):
    associations = {}
    origin = None
    with PcapReader(str(path)) as packets:
        for frame, packet in enumerate(packets, 1):
            if origin is None:
                origin = float(packet.time)
            if IP not in packet or SCTP not in packet:
                continue
            sctp = packet[SCTP]
            if not {sctp.sport, sctp.dport} & {36421, 36422}:
                continue
            key = (packet[IP].src, sctp.sport, packet[IP].dst, sctp.dport, sctp.tag)
            chunks = associations.setdefault(key, {})
            layer = sctp.payload
            while not isinstance(layer, NoPayload):
                if isinstance(layer, SCTPChunkData):
                    # A retransmission or duplicate interface observation has the
                    # same TSN. Retain its first captured occurrence.
                    value = {"frame": frame, "time": float(packet.time) - origin,
                             "tsn": int(layer.tsn), "stream": int(layer.stream_id), "sequence": int(layer.stream_seq),
                             "unordered": int(layer.unordered), "begin": bool(layer.beginning), "end": bool(layer.ending),
                              "data": bytes(layer.data)}
                    if value["tsn"] in chunks and chunks[value["tsn"]]["data"] != value["data"]:
                        raise ValueError("Conflicting SCTP retransmission payload")
                    chunks.setdefault(value["tsn"], value)
                layer = layer.payload
    output, incomplete = [], []
    for association, chunks in associations.items():
        if not chunks:
            continue
        # Captures can contain an out-of-order fragment or cross TSN wrap.
        # Lab captures span far fewer than 2**31 TSNs per association.
        base = min(chunks)
        if max(chunks) - base > 2 ** 31:
            base = min(tsn for tsn in chunks if tsn >= 2 ** 31)
        pending = {}
        for chunk in sorted(chunks.values(), key=lambda c: (c["tsn"] - base) % (2 ** 32)):
            key = (chunk["stream"], chunk["sequence"], chunk["unordered"])
            if chunk["begin"]:
                if key in pending:
                    incomplete.append(pending.pop(key)["frames"])
                pending[key] = {"frames": [], "data": b"", "time": chunk["time"], "last_tsn": None,
                                "source": f"{association[0]}:{association[1]}",
                                 "destination": f"{association[2]}:{association[3]}"}
            if key not in pending:
                incomplete.append([chunk["frame"]])
                continue
            item = pending[key]
            if item["last_tsn"] is not None and (chunk["tsn"] - item["last_tsn"]) % (2 ** 32) != 1:
                incomplete.append(item["frames"] + [chunk["frame"]])
                del pending[key]
                continue
            item["frames"].append(chunk["frame"])
            item["data"] += chunk["data"]
            item["last_tsn"] = chunk["tsn"]
            if chunk["end"]:
                output.append(pending.pop(key))
        incomplete.extend(item["frames"] for item in pending.values())
    return sorted(output, key=lambda item: item["time"]), incomplete


def decode(program, data):
    result = subprocess.run([str(BIN / program)], input=data, capture_output=True, timeout=5)
    if result.returncode:
        raise ValueError(result.stderr.decode(errors="replace").strip() or f"Decoder exited {result.returncode}")
    return result.stdout.decode()


def name(tag):
    return tag.rsplit("}", 1)[-1].replace("-", "").replace("_", "").lower()


def main():
    if len(sys.argv) != 2:
        raise SystemExit("Usage: inspect-control.py CAPTURE.pcap")
    path = Path(sys.argv[1]).resolve()
    records, incomplete = messages(path)
    details = path.with_name(path.name + ".messages.txt")
    with details.open("w") as handle:
        for item in records:
            xml = decode("ai_ran_decode_e2", item["data"])
            root = ET.fromstring(xml)
            envelope = next(iter(root))
            value = envelope.find("value")
            message = next(iter(value)).tag if value is not None and len(value) else envelope.tag
            header = f"Frames {item['frames']}  t={item['time']:.6f}s  {item['source']} -> {item['destination']}  {message}"
            print(header)
            handle.write(header + "\n" + xml + "\n")
            for node in root.iter():
                if name(node.tag) != "riccontrolmessage" or not node.text:
                    continue
                rc_xml = decode("ai_ran_decode_rc", bytes.fromhex(node.text))
                handle.write("Nested E2SM-RC control message:\n" + rc_xml + "\n")
    print("Details:", details)
    if incomplete:
        raise SystemExit(f"Incomplete SCTP message fragments: {incomplete}; capture the full exchange")
    if not records:
        raise SystemExit("No complete E2/E42 DATA messages found on SCTP ports 36421/36422")


if __name__ == "__main__":
    main()
