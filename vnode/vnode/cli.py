from __future__ import annotations

import argparse

from .runtime import VirtualNode


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Virtual Meshtastic node")
    parser.add_argument(
        "--vnode-file",
        "--config",
        dest="vnode_file",
        default="node.json",
        help="Path to node.json",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("run", help="Run the virtual node listener and nodeinfo broadcaster")

    send_text = subparsers.add_parser("send-text", help="Send a text message")
    send_text.add_argument("--to", required=True, help="Destination node id, name, or hex suffix")
    send_text.add_argument("--message", required=True, help="Text to send")
    send_text.add_argument(
        "--pki",
        choices=("auto", "on", "off"),
        default="auto",
        help="PKI mode for direct messages",
    )

    send_nodeinfo = subparsers.add_parser("send-nodeinfo", help="Broadcast or unicast nodeinfo")
    send_nodeinfo.add_argument(
        "--to",
        default="!ffffffff",
        help="Destination node id; default is broadcast",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "run":
        node = VirtualNode(args.vnode_file)
        node.run_forever()
        return 0

    if args.command == "send-text":
        node = VirtualNode(args.vnode_file)
        packet_id = node.send_text(args.to, args.message, pki_mode=args.pki)
        print(packet_id)
        return 0

    if args.command == "send-nodeinfo":
        node = VirtualNode(args.vnode_file)
        packet_id = node.send_nodeinfo(destination=node._resolve_destination(args.to))
        print(packet_id)
        return 0

    parser.error(f"Unknown command {args.command}")
    return 2
