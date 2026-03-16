from __future__ import annotations

import sys
import time
from pathlib import Path

from meshtastic import BROADCAST_ADDR
from meshtastic.protobuf import portnums_pb2

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
DESTINATION_ID = BROADCAST_ADDR


def onReceive(packet, interface) -> None:
    del interface
    print(
        f"[RX] from={packet.get('from')} to={packet.get('to')} "
        f"port={packet.get('decoded', {}).get('portnum')}"
    )


def main() -> int:
    node = VirtualNode(VNODE_FILE)
    node.receive(onReceive)

    try:
        node.start()
        print(
            f"[NODE] {node.getLongName()} ({node.getShortName()}) "
            f"public_key={bool(node.getPublicKey())}"
        )

        # text_packet = node.sendText("hello from sendText()", destinationId=DESTINATION_ID)
        # print(f"[SEND] sendText packet_id={text_packet.id}")

        alert_packet = node.sendAlert("compat alert", destinationId=DESTINATION_ID)
        print(f"[SEND] sendAlert packet_id={alert_packet.id}")

        data_packet = node.sendData(
            b"raw private payload",
            destinationId=DESTINATION_ID,
            portNum=portnums_pb2.PortNum.PRIVATE_APP,
        )
        print(f"[SEND] sendData packet_id={data_packet.id}")

        position_packet = node.sendPosition(
            latitude=45.523064,
            longitude=-122.676483,
            altitude=27,
            destinationId=DESTINATION_ID,
        )
        print(f"[SEND] sendPosition packet_id={position_packet.id}")

        while True:
            time.sleep(0.1)
    except KeyboardInterrupt:
        return 0
    finally:
        node.unreceive(onReceive)
        node.close()


if __name__ == "__main__":
    raise SystemExit(main())
