from __future__ import annotations

import sys
import time
from pathlib import Path

import meshtastic.serial_interface
import meshtastic.util
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


VNODE_FILE = "node.json"
SERIAL_DEVICE = None


def onReceive(packet, interface) -> None:
    print(f"{packet}\n")

def main() -> int:
    serial = None
    vnode_node = None

    try:
        device = SERIAL_DEVICE or next(iter(meshtastic.util.findPorts(True)), None)
        if device is None:
            raise RuntimeError("no serial device attached")
        serial = meshtastic.serial_interface.SerialInterface(devPath=device, timeout=5)
        pub.subscribe(onReceive, "meshtastic.receive")
        print(f"[SERIAL] Connected to {device}")
    except Exception as exc:
        vnode_node = VirtualNode(VNODE_FILE)
        vnode_node.receive(onReceive)
        vnode_node.start()
        print(
            f"[VNODE] Serial connection unavailable ({exc}); "
            f"using {vnode_node.config.long_name} ({vnode_node.config.node_id}) "
            f"on channel {vnode_node.config.channel.name}"
        )

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        if serial is not None:
            try:
                pub.unsubscribe(onReceive, "meshtastic.receive")
            except KeyError:
                pass
            serial.close()
        if vnode_node is not None:
            vnode_node.unreceive(onReceive)
            vnode_node.stop()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
