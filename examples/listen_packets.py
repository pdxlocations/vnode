from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from meshtastic.protobuf import mesh_pb2, portnums_pb2
from pubsub import pub

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    # Allow running this script directly from the repository root.
    sys.path.insert(0, str(REPO_ROOT))

from vnode.runtime import VirtualNode


class PacketPrinter:
    def __init__(self, node: VirtualNode) -> None:
        self.node = node

    def on_packet(self, packet: mesh_pb2.MeshPacket, addr=None) -> None:
        # Try PKI decode before printing so direct messages show readable payloads.
        if not packet.HasField("decoded"):
            self.node._try_decode_pki(packet)

        source = getattr(packet, "from", 0)
        destination = getattr(packet, "to", 0)
        summary = (
            f"[PACKET] id={packet.id} from=!{int(source):08x} to=!{int(destination):08x} "
            f"want_ack={bool(getattr(packet, 'want_ack', False))} "
            f"hop={packet.hop_limit}/{packet.hop_start} "
            f"addr={addr}"
        )
        if packet.HasField("decoded"):
            summary += f" portnum={packet.decoded.portnum}"
        elif packet.encrypted:
            summary += " portnum=<encrypted>"
        print(summary)

        if packet.HasField("decoded") and packet.decoded.portnum == portnums_pb2.PortNum.TEXT_MESSAGE_APP:
            message = packet.decoded.payload.decode("utf-8", "ignore")
            print(f"         text={message}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Print incoming packets")
    parser.add_argument("--config", default="node.json", help="Path to node.json")
    args = parser.parse_args()

    node = VirtualNode(args.config)
    printer = PacketPrinter(node)

    node.start()
    # Listen to the vnode runtime's deduplicated packet topic.
    pub.subscribe(printer.on_packet, VirtualNode.PACKET_TOPIC)
    print("Listening for packets.")

    try:
        while True:
            time.sleep(0.05)
    except KeyboardInterrupt:
        return 0
    finally:
        try:
            pub.unsubscribe(printer.on_packet, VirtualNode.PACKET_TOPIC)
        except KeyError:
            pass
        node.stop()


if __name__ == "__main__":
    raise SystemExit(main())
