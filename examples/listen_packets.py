from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from meshtastic.protobuf import mesh_pb2, portnums_pb2
from pubsub import pub

try:
    from vnode import VirtualNode
except ImportError:
    REPO_ROOT = Path(__file__).resolve().parents[1]
    SOURCE_ROOT = REPO_ROOT / "vnode"
    if str(SOURCE_ROOT) not in sys.path:
        # Allow running this script directly from the repository root.
        sys.path.insert(0, str(SOURCE_ROOT))
    from vnode import VirtualNode


class PacketPrinter:
    def __init__(self, node: VirtualNode) -> None:
        self.node = node

    def on_packet(self, packet: mesh_pb2.MeshPacket, addr=None) -> None:
        # Packets on the app-facing topic are already deduplicated, but PKI DMs may still need
        # local decryption before their decoded payload is visible.
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

        # Show text payloads separately so it is easy to scan the log output.
        if packet.HasField("decoded") and packet.decoded.portnum == portnums_pb2.PortNum.TEXT_MESSAGE_APP:
            message = packet.decoded.payload.decode("utf-8", "ignore")
            print(f"         text={message}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Print incoming packets")
    parser.add_argument(
        "--vnode-file",
        "--config",
        dest="vnode_file",
        default="node.json",
        help="Path to node.json",
    )
    args = parser.parse_args()

    # This is the minimal "listener" shape for an app using vnode as a library.
    node = VirtualNode(args.vnode_file)
    printer = PacketPrinter(node)

    node.start()
    # Subscribe to the runtime's deduplicated topic so repeated multicast copies do not spam logs.
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
        # Stop the node to close sockets and stop the broadcast thread.
        node.stop()


if __name__ == "__main__":
    raise SystemExit(main())
