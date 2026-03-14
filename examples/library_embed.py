from __future__ import annotations

import sys
import time
from pathlib import Path

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


# Edit these values to match how your application wants to construct and use the node.
VNODE_FILE = "node.json"
STARTUP_DESTINATION = None
STARTUP_MESSAGE = "hello from an embedded vnode"


def on_packet(packet, addr=None) -> None:
    del addr
    # In an embedded app, this callback is where you would dispatch packets into your own logic.
    source = getattr(packet, "from", 0)
    destination = getattr(packet, "to", 0)
    print(f"[RX] id={packet.id} from=!{int(source):08x} to=!{int(destination):08x}")

    # Public helper: only treat direct messages addressed to this node as "incoming chats".
    if EMBEDDED_NODE is not None and EMBEDDED_NODE.is_direct_message_for_me(packet):
        print("     packet is a direct message for this node")

    # Public helper: extract human-readable text when the packet is a text message.
    if EMBEDDED_NODE is not None:
        text = EMBEDDED_NODE.get_text_message(packet)
        if text is not None:
            print(f"     text={text}")

    # Public helper: reply_to_packet() sends a threaded reply that preserves reply_id and hop settings.
    # Example:
    # if EMBEDDED_NODE is not None and EMBEDDED_NODE.is_direct_message_for_me(packet):
    #     EMBEDDED_NODE.reply_to_packet(packet, "message received")


def show_public_api_examples(node: VirtualNode) -> None:
    print("[API] Common public VirtualNode calls you can use from application code:")
    print(f"      node.config.node_id -> {node.config.node_id}")
    print(f"      node.node_num -> !{node.node_num:08x}")
    print(f"      node.public_key_path -> {node.public_key_path}")
    print(f"      node.meshdb_path -> {node.meshdb_path}")
    print("      node.start() / node.stop()")
    print("      node.send_text('!1234abcd', 'hello')")
    print("      node.send_reply('!1234abcd', 'hello', reply_id=123)")
    print("      node.send_nodeinfo()")
    print("      node.send_position()  # requires position.enabled and coordinates in node.json")
    print("      node.is_direct_message_for_me(packet)")
    print("      node.is_text_message(packet)")
    print("      node.get_text_message(packet)")
    print("      node.reply_to_packet(packet, 'message received')")


EMBEDDED_NODE: VirtualNode | None = None


def main() -> int:
    # This is the basic application-side embedding pattern:
    # 1. Build the node from a config file.
    # 2. Subscribe your app callbacks.
    # 3. Start the node.
    # 4. Use the public API while it is running.
    # 5. Stop it in finally.
    global EMBEDDED_NODE
    node = VirtualNode(VNODE_FILE)
    EMBEDDED_NODE = node
    # Subscribe to the deduplicated packet topic so the app sees one callback per packet.
    pub.subscribe(on_packet, VirtualNode.PACKET_TOPIC)

    try:
        node.start()
        print(f"[START] Embedded vnode running as {node.config.node_id}")
        show_public_api_examples(node)

        # Public API example: broadcast your node info on startup.
        nodeinfo_packet_id = node.send_nodeinfo()
        print(f"[SEND] nodeinfo packet_id={nodeinfo_packet_id}")

        if STARTUP_DESTINATION:
            # This shows that app code can call the normal public send API directly.
            packet_id = node.send_text(STARTUP_DESTINATION, STARTUP_MESSAGE)
            print(f"[SEND] packet_id={packet_id}")

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
        try:
            pub.unsubscribe(on_packet, VirtualNode.PACKET_TOPIC)
        except KeyError:
            pass
        # node.stop() closes sockets and stops background work started by node.start().
        node.stop()
        EMBEDDED_NODE = None
        print("[STOP] Embedded vnode stopped")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
