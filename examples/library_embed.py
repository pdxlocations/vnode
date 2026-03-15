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


# Edit these values to match how your application wants to construct and use the node.
VNODE_FILE = "node.json"
STARTUP_DESTINATION = None
STARTUP_MESSAGE = "hello from an embedded vnode"


def on_receive(packet, interface) -> None:
    del interface
    # This is the Meshtastic-compatible receive shape: packet dict + interface.
    source = int(packet.get("from", 0) or 0)
    destination = int(packet.get("to", 0) or 0)
    print(f"[RX] id={packet.get('id')} from=!{source:08x} to=!{destination:08x}")
    decoded = packet.get("decoded", {})
    if isinstance(decoded, dict) and decoded.get("text"):
        print(f"     text={decoded.get('text')}")


def show_public_api_examples(node: VirtualNode) -> None:
    print("[API] Common public VirtualNode calls you can use from application code:")
    print(f"      node.config.node_id -> {node.config.node_id}")
    print(f"      node.node_num -> !{node.node_num:08x}")
    print(f"      node.public_key_path -> {node.public_key_path}")
    print(f"      node.meshdb_path -> {node.meshdb_path}")
    print("      node.start() / node.stop()")
    print("      node.receive(on_receive) / node.unreceive(on_receive)")
    print("      node.close()")
    print("      node.send_text('!1234abcd', 'hello')")
    print("      node.sendText('hello', destinationId='!1234abcd')")
    print("      node.send_reply('!1234abcd', 'hello', reply_id=123)")
    print("      node.send_nodeinfo()")
    print("      node.sendPosition(latitude=45.52, longitude=-122.67)")
    print("      node.send_position()  # requires position.enabled and coordinates in node.json")
    print("      node.getMyNodeInfo() / node.getMyUser() / node.getLongName()")
    print("      node.is_direct_message_for_me(packet)")
    print("      node.is_text_message(packet)")
    print("      node.get_text_message(packet)")
    print("      node.reply_to_packet(packet, 'message received')")


def main() -> int:
    # This is the basic application-side embedding pattern:
    # 1. Build the node from a config file.
    # 2. Register a receive callback.
    # 3. Start the node.
    # 4. Use the public API while it is running.
    # 5. Stop it in finally.
    node = VirtualNode(VNODE_FILE)
    # receive() mirrors meshtastic.receive(packet, interface).
    node.receive(on_receive)

    try:
        node.start()
        print(f"[START] Embedded vnode running as {node.config.node_id}")
        show_public_api_examples(node)

        # Public API example: broadcast your node info on startup.
        nodeinfo_packet_id = node.send_nodeinfo()
        print(f"[SEND] nodeinfo packet_id={nodeinfo_packet_id}")

        if STARTUP_DESTINATION:
            # Both vnode snake_case and Meshtastic-style camelCase sends are available.
            packet_id = node.send_text(STARTUP_DESTINATION, STARTUP_MESSAGE)
            print(f"[SEND] packet_id={packet_id}")
            node.sendText(STARTUP_MESSAGE, destinationId=STARTUP_DESTINATION)

        # Public API example: position sending uses the values from node.json when enabled.
        # Example:
        # node.send_position()
        #
        # Public API example: you can override the configured position for one send.
        # Example:
        # node.send_position(latitude=45.52, longitude=-122.67, altitude=27)

        # Embedded applications usually keep their node alive for the lifetime of the process.
        while True:
            time.sleep(0.1)
    except KeyboardInterrupt:
        return 0
    finally:
        node.unreceive(on_receive)
        # close() is a Meshtastic-style alias for stop().
        node.close()
        print("[STOP] Embedded vnode stopped")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
