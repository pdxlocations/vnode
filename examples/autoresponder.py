from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from meshtastic.protobuf import mesh_pb2
from pubsub import pub

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    # Allow running this script directly from the repository root.
    sys.path.insert(0, str(REPO_ROOT))

from vnode.runtime import VirtualNode


class DirectMessageAutoResponder:
    def __init__(self, node: VirtualNode) -> None:
        self.node = node
        self.reply_with_emoji = True

    def on_packet(self, packet: mesh_pb2.MeshPacket, addr=None) -> None:
        del addr
        if not self.node.is_text_message(packet):
            return
        # This example only answers direct messages addressed to this node.
        if not self.node.is_direct_message_for_me(packet):
            return

        sender_id = getattr(packet, "from", None)
        if packet.decoded.reply_id:
            print(f"[SKIP] Packet {packet.id} is already a reply to {packet.decoded.reply_id}")
            return

        message = self.node.get_text_message(packet)
        if message is None:
            return
        print(f"\n[RECV] From: !{int(sender_id):08x} Message: {message}")

        if self.reply_with_emoji:
            reply_message = "👍"
            emoji = True
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
    parser.add_argument("--config", default="node.json", help="Path to node.json")
    args = parser.parse_args()

    node = VirtualNode(args.config)
    responder = DirectMessageAutoResponder(node)

    node.start()
    # Subscribe after the node starts so the UDP listener is already active.
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
        node.stop()


if __name__ == "__main__":
    raise SystemExit(main())
