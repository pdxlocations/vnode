from __future__ import annotations

import argparse
import random
import sys
import time
from pathlib import Path

from meshtastic import BROADCAST_NUM
from meshtastic.protobuf import mesh_pb2, portnums_pb2

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
        self.local_node_label = (
            f"{self.node.config.long_name} ({self.node.config.short_name}, {self.node.config.node_id})"
        )
        # Alternate between a threaded emoji reaction and a normal DM so both send styles are visible.
        self.reply_with_emoji = True
        # Keep the reply a little slower than a machine-like instant echo.
        self.min_reply_delay_seconds = 0.8
        self.max_reply_delay_seconds = 1.8
        self._wrap_send_nodeinfo()

    @staticmethod
    def _format_node_num(node_num: int | None) -> str:
        if node_num is None:
            return "unknown"
        return f"!{int(node_num):08x}"

    def _format_destination(self, destination: int) -> str:
        if int(destination) == BROADCAST_NUM:
            return "broadcast"
        return self._format_node_num(int(destination))

    def _wrap_send_nodeinfo(self) -> None:
        original_send_nodeinfo = self.node._send_nodeinfo

        def logged_send_nodeinfo(
            destination: int = BROADCAST_NUM,
            *,
            request_id: int | None = None,
            want_ack: bool = False,
        ) -> int:
            packet_id = original_send_nodeinfo(
                destination,
                request_id=request_id,
                want_ack=want_ack,
            )
            if request_id is None:
                print(
                    f"[NODEINFO] {self.local_node_label} sent nodeinfo to "
                    f"{self._format_destination(destination)} as packet {packet_id}"
                )
            else:
                print(
                    f"[NODEINFO] {self.local_node_label} replied with nodeinfo to "
                    f"{self._format_destination(destination)} for request {request_id} "
                    f"as packet {packet_id}"
                )
            return packet_id

        self.node._send_nodeinfo = logged_send_nodeinfo

    def on_receive(self, packet: dict, interface=None) -> None:
        raw_packet = packet.get("raw")
        if not isinstance(raw_packet, mesh_pb2.MeshPacket):
            return

        if (
            raw_packet.decoded.portnum == portnums_pb2.PortNum.NODEINFO_APP
            and int(getattr(raw_packet, "to", BROADCAST_NUM)) == self.node.node_num
            and getattr(raw_packet, "from", None) not in (None, self.node.node_num)
            and getattr(raw_packet.decoded, "want_response", False)
        ):
            print(
                f"[NODEINFO] Request from {self._format_node_num(int(getattr(raw_packet, 'from')))} "
                f"to {self.local_node_label} on channel {self.node.config.channel.name} "
                f"for packet {raw_packet.id}"
            )

        # Ignore everything except decoded text packets.
        if not self.node.is_text_message(raw_packet):
            return
        # This example only answers direct messages addressed to this node.
        if not self.node.is_direct_message_for_me(raw_packet):
            return

        sender_id = getattr(raw_packet, "from", None)
        # Ignore replies so the bot does not create reply chains with other bots or users.
        if raw_packet.decoded.reply_id:
            print(f"[SKIP] Packet {raw_packet.id} is already a reply to {raw_packet.decoded.reply_id}")
            return

        message = packet.get("decoded", {}).get("text")
        if not isinstance(message, str):
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
                raw_packet,
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
            f"for message {raw_packet.id} as packet {reply_packet_id}: {reply_message}"
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

    print(
        f"[NODE] Local node: {responder.local_node_label} "
        f"as {responder._format_node_num(node.node_num)} "
        f"on channel {node.config.channel.name}"
    )
    node.start()
    node.receive(responder.on_receive)

    print("DM autoresponder listening for text messages.")
    print("Replies are always sent as direct messages.")
    print("Replies alternate between an emoji and plain text.")

    try:
        while True:
            time.sleep(0.05)
    except KeyboardInterrupt:
        return 0
    finally:
        node.unreceive(responder.on_receive)
        # Always stop the node so sockets and background threads are cleaned up.
        node.stop()


if __name__ == "__main__":
    raise SystemExit(main())
