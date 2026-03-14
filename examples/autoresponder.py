from __future__ import annotations

import argparse
import random
import sys
import time
from pathlib import Path

from meshtastic.protobuf import mesh_pb2
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


class DirectMessageAutoResponder:
    def __init__(self, node: VirtualNode) -> None:
        self.node = node
        # Alternate between a threaded emoji reaction and a normal DM so both send styles are visible.
        self.reply_with_emoji = True
        # Keep the reply a little slower than a machine-like instant echo.
        self.min_reply_delay_seconds = 0.8
        self.max_reply_delay_seconds = 1.8

    def on_packet(self, packet: mesh_pb2.MeshPacket, addr=None) -> None:
        del addr
        # Ignore everything except decoded text packets.
        if not self.node.is_text_message(packet):
            return
        # This example only answers direct messages addressed to this node.
        if not self.node.is_direct_message_for_me(packet):
            return

        sender_id = getattr(packet, "from", None)
        # Ignore replies so the bot does not create reply chains with other bots or users.
        if packet.decoded.reply_id:
            print(f"[SKIP] Packet {packet.id} is already a reply to {packet.decoded.reply_id}")
            return

        # Use the runtime helper so PKI-decoded DMs and normal channel DMs are handled the same way.
        message = self.node.get_text_message(packet)
        if message is None:
            return
        print(f"\n[RECV] From: !{int(sender_id):08x} Message: {message}")

        # The sleep is purely example behavior. It is not part of the transport or ACK logic.
        delay_seconds = random.uniform(
            self.min_reply_delay_seconds,
            self.max_reply_delay_seconds,
        )
        print(f"[WAIT] Sleeping {delay_seconds:.2f}s before replying")
        time.sleep(delay_seconds)

        if self.reply_with_emoji:
            reply_message = "👍"
            emoji = True
            # reply_to_packet() preserves reply_id and hop settings from the inbound packet.
            reply_packet_id = self.node.reply_to_packet(
                packet,
                reply_message,
                emoji=emoji,
                pki_mode="auto",
            )
            reply_kind = "reply"
        else:
            reply_message = "message received"
            emoji = False
            # send_text() creates a fresh direct message instead of a threaded reply.
            reply_packet_id = self.node.send_text(
                int(sender_id),
                reply_message,
                pki_mode="auto",
            )
            reply_kind = "dm"
        print(
            f"[REPLY] Sent {'emoji' if emoji else 'text'} {reply_kind} to !{int(sender_id):08x} "
            f"for message {packet.id} as packet {reply_packet_id}: {reply_message}"
        )

        self.reply_with_emoji = not self.reply_with_emoji


def main() -> int:
    parser = argparse.ArgumentParser(description="DM-only autoresponder example")
    parser.add_argument(
        "--vnode-file",
        "--config",
        dest="vnode_file",
        default="node.json",
        help="Path to node.json",
    )
    args = parser.parse_args()

    # Applications usually construct one VirtualNode from a config file and keep it around.
    node = VirtualNode(args.vnode_file)
    responder = DirectMessageAutoResponder(node)

    node.start()
    # Subscribe to the deduplicated packet topic so app code sees each packet once.
    # The runtime still processes raw packets internally for ACK and PKI decode behavior.
    pub.subscribe(responder.on_packet, VirtualNode.PACKET_TOPIC)

    print("DM autoresponder listening for text messages.")
    print("Replies are always sent as direct messages.")
    print("Replies alternate between an emoji and plain text.")

    try:
        while True:
            time.sleep(0.05)
    except KeyboardInterrupt:
        return 0
    finally:
        try:
            pub.unsubscribe(responder.on_packet, VirtualNode.PACKET_TOPIC)
        except KeyError:
            pass
        # Always stop the node so sockets and background threads are cleaned up.
        node.stop()


if __name__ == "__main__":
    raise SystemExit(main())
