from __future__ import annotations

import argparse
import sys
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


def main() -> int:
    parser = argparse.ArgumentParser(description="Send a direct message")
    parser.add_argument(
        "--vnode-file",
        "--config",
        dest="vnode_file",
        default="node.json",
        help="Path to node.json",
    )
    parser.add_argument("--to", required=True, help="Destination node id, name, or hex suffix")
    parser.add_argument("--message", required=True, help="Text to send")
    parser.add_argument(
        "--pki",
        choices=("auto", "on", "off"),
        default="auto",
        help="PKI mode for direct messages",
    )
    args = parser.parse_args()

    # For a one-shot sender, constructing the node is enough; no long-running loop is required.
    node = VirtualNode(args.vnode_file)
    # The runtime chooses PKI automatically when the destination has a stored public key.
    # Otherwise the DM falls back to normal channel encryption.
    packet_id = node.send_text(args.to, args.message, pki_mode=args.pki)
    print(packet_id)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
