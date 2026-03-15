from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

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

    def on_packet(self, packet, interface) -> None:
        del interface
        # node.receive() mirrors meshtastic.receive(packet, interface) with a packet dictionary.
        source = int(packet.get("from", 0) or 0)
        destination = int(packet.get("to", 0) or 0)
        decoded = packet.get("decoded", {})
        summary = (
            f"[PACKET] id={packet.get('id')} from=!{source:08x} to=!{destination:08x} "
            f"want_ack={bool(packet.get('wantAck', False))} "
            f"hop={packet.get('hopLimit')}/{packet.get('hopStart')}"
        )
        if isinstance(decoded, dict) and decoded.get("portnum") is not None:
            summary += f" portnum={decoded.get('portnum')}"
        elif packet.get("encrypted"):
            summary += " portnum=<encrypted>"
        print(summary)

        # Mirrored text packets expose decoded.text like the Meshtastic Python library.
        if isinstance(decoded, dict) and decoded.get("text"):
            print(f"         text={decoded.get('text')}")


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
    # Use the mirrored Meshtastic receive callback shape.
    node.receive(printer.on_packet)
    print("Listening for packets.")

    try:
        while True:
            time.sleep(0.05)
    except KeyboardInterrupt:
        return 0
    finally:
        node.unreceive(printer.on_packet)
        node.stop()


if __name__ == "__main__":
    raise SystemExit(main())
