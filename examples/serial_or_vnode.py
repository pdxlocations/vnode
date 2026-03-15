import time
import meshtastic.serial_interface
import meshtastic.util
from pubsub import pub
from vnode import VirtualNode

VNODE_FILE = "node.json"
SERIAL_DEVICE = None

def on_receive(packet, interface) -> None:
    del interface
    # Both serial Meshtastic and vnode call this as (packet_dict, interface).
    print(packet)
    print()

def main() -> int:
    serial = None
    vnode = None

    try:
        device = SERIAL_DEVICE or next(iter(meshtastic.util.findPorts(True)), None)
        if device is None:
            raise RuntimeError("no serial device attached")
        serial = meshtastic.serial_interface.SerialInterface(devPath=device, timeout=5)
        pub.subscribe(on_receive, "meshtastic.receive")
        print(f"connected by serial: {device}")
    except Exception:
        vnode = VirtualNode(VNODE_FILE)
        vnode.receive(on_receive)
        vnode.start()
        print(f"using vnode {vnode.config.node_id}")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        if serial is not None:
            try:
                pub.unsubscribe(on_receive, "meshtastic.receive")
            except KeyError:
                pass
            serial.close()
        if vnode is not None:
            vnode.unreceive(on_receive)
            vnode.stop()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
