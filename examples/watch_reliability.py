from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from pubsub import pub

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    # Allow running this script directly from the repository root.
    sys.path.insert(0, str(REPO_ROOT))

from vnode.runtime import VirtualNode


def on_ack(packet, routing, addr, pending) -> None:
    del routing
    request_id = packet.decoded.request_id if packet.HasField("decoded") else 0
    print(
        f"[ACK] request_id={request_id} from=!{int(getattr(packet, 'from', 0)):08x} "
        f"pending_cleared={pending is not None} addr={addr}"
    )


def on_nak(packet, routing, addr, pending) -> None:
    request_id = packet.decoded.request_id if packet.HasField("decoded") else 0
    print(
        f"[NAK] request_id={request_id} from=!{int(getattr(packet, 'from', 0)):08x} "
        f"reason={routing.error_reason} pending_cleared={pending is not None} addr={addr}"
    )


def on_retry(pending) -> None:
    print(
        f"[RETRY] packet_id={pending.packet_id} to=!{pending.destination:08x} "
        f"retries_left={pending.retries_left}"
    )


def on_retry_error(pending, error) -> None:
    print(f"[RETRY_ERROR] packet_id={pending.packet_id} error={error}")


def on_max_retransmit(pending, error_reason) -> None:
    print(
        f"[MAX_RETRANSMIT] packet_id={pending.packet_id} to=!{pending.destination:08x} "
        f"reason={error_reason}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Watch ACK/NAK/retry events")
    parser.add_argument("--config", default="node.json", help="Path to node.json")
    parser.add_argument("--to", help="Optional destination node id to send to on startup")
    parser.add_argument("--message", help="Optional message to send on startup")
    args = parser.parse_args()

    node = VirtualNode(args.config)
    node.start()

    # These pubsub topics mirror the reliability events emitted by mudp.
    pub.subscribe(on_ack, "mesh.rx.ack")
    pub.subscribe(on_nak, "mesh.rx.nak")
    pub.subscribe(on_retry, "mesh.tx.retry")
    pub.subscribe(on_retry_error, "mesh.tx.retry_error")
    pub.subscribe(on_max_retransmit, "mesh.tx.max_retransmit")

    if args.to and args.message:
        # Sending an initial DM makes it easy to watch the full ACK/retry lifecycle.
        packet_id = node.send_text(args.to, args.message)
        print(f"[SEND] packet_id={packet_id}")

    print("Watching reliability events.")

    try:
        while True:
            time.sleep(0.05)
    except KeyboardInterrupt:
        return 0
    finally:
        for topic, listener in (
            ("mesh.rx.ack", on_ack),
            ("mesh.rx.nak", on_nak),
            ("mesh.tx.retry", on_retry),
            ("mesh.tx.retry_error", on_retry_error),
            ("mesh.tx.max_retransmit", on_max_retransmit),
        ):
            try:
                pub.unsubscribe(listener, topic)
            except KeyError:
                pass
        node.stop()


if __name__ == "__main__":
    raise SystemExit(main())
