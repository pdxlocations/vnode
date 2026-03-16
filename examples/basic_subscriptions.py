from __future__ import annotations

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


VNODE_FILE = "node.json"


def on_receive(packet, interface=None) -> None:
    del interface
    source = int(packet.get("from", 0))
    destination = int(packet.get("to", 0))
    decoded = packet.get("decoded", {})
    portnum = decoded.get("portnum")

    print(f"[RX] from=!{source:08x} to=!{destination:08x} portnum={portnum}")

    text = decoded.get("text")
    if isinstance(text, str):
        print(f"     text={text}")


def main() -> int:
    node = VirtualNode(VNODE_FILE)
    node.receive(on_receive)

    print(
        f"Listening as {node.config.long_name} ({node.config.node_id}) "
        f"on channel {node.config.channel.name}"
    )

    try:
        node.start()
        while True:
            time.sleep(0.1)
    except KeyboardInterrupt:
        return 0
    finally:
        node.unreceive(on_receive)
        node.stop()


if __name__ == "__main__":
    raise SystemExit(main())
