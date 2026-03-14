from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    # Allow running this script directly from the repository root.
    sys.path.insert(0, str(REPO_ROOT))

from vnode.runtime import VirtualNode


def main() -> int:
    parser = argparse.ArgumentParser(description="Send a direct message")
    parser.add_argument("--config", default="node.json", help="Path to node.json")
    parser.add_argument("--to", required=True, help="Destination node id, name, or hex suffix")
    parser.add_argument("--message", required=True, help="Text to send")
    parser.add_argument(
        "--pki",
        choices=("auto", "on", "off"),
        default="auto",
        help="PKI mode for direct messages",
    )
    args = parser.parse_args()

    node = VirtualNode(args.config)
    # The runtime decides whether to use PKI or channel encryption from the destination state.
    packet_id = node.send_text(args.to, args.message, pki_mode=args.pki)
    print(packet_id)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
