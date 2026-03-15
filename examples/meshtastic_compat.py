import time
from pubsub import pub
from vnode import VirtualNode



VNODE_FILE = "node.json"
STARTUP_TEXT = "hello mesh"


def on_connection(interface) -> None:
    # This mirrors meshtastic.connection.established from the Python library.
    print(f"[CONNECT] {interface.getLongName()} {interface.config.node_id}")
    print(f"[ME] {interface.getMyNodeInfo()}")
    interface.sendText(STARTUP_TEXT)


def on_receive(packet, interface) -> None:
    # This mirrors meshtastic.receive and passes the interface as the second arg.
    print(f"[RECV] {packet}")


def on_node_updated(node, interface) -> None:
    print(f"[NODE] {node}")


def on_log_line(line, interface) -> None:
    print(f"[LOG] {line}")


def main() -> int:
    node = VirtualNode(VNODE_FILE)
    pub.subscribe(on_connection, "meshtastic.connection.established")
    pub.subscribe(on_receive, "meshtastic.receive")
    pub.subscribe(on_node_updated, "meshtastic.node.updated")
    pub.subscribe(on_log_line, "meshtastic.log.line")

    try:
        node.start()
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        try:
            pub.unsubscribe(on_connection, "meshtastic.connection.established")
        except KeyError:
            pass
        try:
            pub.unsubscribe(on_receive, "meshtastic.receive")
        except KeyError:
            pass
        try:
            pub.unsubscribe(on_node_updated, "meshtastic.node.updated")
        except KeyError:
            pass
        try:
            pub.unsubscribe(on_log_line, "meshtastic.log.line")
        except KeyError:
            pass
        node.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
