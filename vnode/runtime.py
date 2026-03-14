from __future__ import annotations

import random
import threading
import time
from pathlib import Path
from typing import Any

import meshdb
from google.protobuf.message import DecodeError
from meshtastic import BROADCAST_NUM, config_pb2, mesh_pb2, portnums_pb2
from mudp import UDPPacketStream
from mudp.encryption import encrypt_packet as mudp_encrypt_packet
from mudp.reliability import is_ack, is_nak, publish_ack, register_pending_ack, send_ack
from mudp.singleton import conn, node as mudp_node
from pubsub import pub

from .config import NodeConfig
from .crypto import b64_decode, b64_encode, decrypt_dm, derive_public_key, encrypt_dm, generate_keypair

PKI_DISALLOWED_PORTNUMS = {
    portnums_pb2.PortNum.TRACEROUTE_APP,
    portnums_pb2.PortNum.NODEINFO_APP,
    portnums_pb2.PortNum.ROUTING_APP,
    portnums_pb2.PortNum.POSITION_APP,
}
TEXT_PORTNUMS = {
    portnums_pb2.PortNum.TEXT_MESSAGE_APP,
    portnums_pb2.PortNum.TEXT_MESSAGE_COMPRESSED_APP,
}


def parse_node_id(node_id: str | int) -> int:
    if isinstance(node_id, int):
        return node_id
    text = str(node_id).strip()
    if text.startswith("!"):
        text = text[1:]
    return int(text, 16)


def resolve_hw_model(value: str | int) -> int:
    if isinstance(value, int):
        return value
    return mesh_pb2.HardwareModel.Value(str(value))


def resolve_role(value: str | int) -> int:
    if isinstance(value, int):
        return value
    return config_pb2.Config.DeviceConfig.Role.Value(str(value))


class VirtualNode:
    PACKET_TOPIC = "mesh.rx.unique_packet"
    DUPLICATE_TOPIC = "mesh.rx.duplicate"

    def __init__(self, config_path: str | Path = "node.json") -> None:
        self.config_path = Path(config_path).resolve()
        self.base_dir = self.config_path.parent
        self.public_key_path = self.config_path.with_suffix(".public.key")
        self.config = NodeConfig.load(self.config_path)
        self.node_num = parse_node_id(self.config.node_id)
        self.meshdb_path = str((self.base_dir / self.config.meshdb.path).resolve())
        self.stream: UDPPacketStream | None = None
        self._stop = threading.Event()
        self._broadcast_thread: threading.Thread | None = None
        self._message_id = random.getrandbits(32)
        self._public_key_b64 = ""

        self._ensure_security_keys()
        self._write_public_key_file()
        self._seed_owner_record()
        self._configure_mudp_globals()

    def _ensure_security_keys(self) -> None:
        private_key = self.config.security.private_key.strip()
        changed = False

        if private_key:
            self._public_key_b64 = b64_encode(derive_public_key(b64_decode(private_key)))
        else:
            public_bytes, private_bytes = generate_keypair()
            self._public_key_b64 = b64_encode(public_bytes)
            private_key = b64_encode(private_bytes)
            changed = True

        if changed:
            self.config.security.private_key = private_key
            self.config.security.public_key = ""
            self.config.save(self.config_path)

    def _write_public_key_file(self) -> None:
        if not self._public_key_b64:
            return
        self.public_key_path.write_text(f"{self._public_key_b64}\n", encoding="utf-8")

    def _seed_owner_record(self) -> None:
        Path(self.meshdb_path).mkdir(parents=True, exist_ok=True)
        meshdb.set_default_db_path(self.meshdb_path)
        meshdb.NodeDB(self.node_num, self.meshdb_path).upsert(
            node_num=self.node_num,
            long_name=self.config.long_name,
            short_name=self.config.short_name,
            hw_model=str(resolve_hw_model(self.config.hw_model)),
            role=str(self.config.role),
            is_licensed=int(self.config.is_licensed),
            public_key=self._public_key_b64,
        )

    def _configure_mudp_globals(self) -> None:
        mudp_node.node_id = self.config.node_id
        mudp_node.long_name = self.config.long_name
        mudp_node.short_name = self.config.short_name
        mudp_node.hw_model = resolve_hw_model(self.config.hw_model)
        mudp_node.role = self.config.role
        mudp_node.public_key = (
            b64_decode(self._public_key_b64)
            if self._public_key_b64
            else b""
        )
        mudp_node.channel = self.config.channel.name
        mudp_node.key = self.config.channel.psk

    def start(self) -> None:
        if self.stream is not None:
            return
        pub.subscribe(self._handle_raw_packet, "mesh.rx.packet")
        pub.subscribe(self._handle_unique_packet, self.PACKET_TOPIC)
        pub.subscribe(self._handle_listener_error, "mesh.rx.listener_error")
        self.stream = UDPPacketStream(
            self.config.udp.mcast_group,
            int(self.config.udp.mcast_port),
            key=self.config.channel.psk,
            parse_payload=False,
        )
        self.stream.start()
        if self.config.broadcasts.send_startup_nodeinfo:
            self.send_nodeinfo()
        self._broadcast_thread = threading.Thread(
            target=self._broadcast_loop,
            name="vnode-nodeinfo-broadcast",
            daemon=True,
        )
        self._broadcast_thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self.stream is not None:
            self.stream.stop()
            self.stream = None
        try:
            pub.unsubscribe(self._handle_raw_packet, "mesh.rx.packet")
        except KeyError:
            pass
        try:
            pub.unsubscribe(self._handle_unique_packet, self.PACKET_TOPIC)
        except KeyError:
            pass
        try:
            pub.unsubscribe(self._handle_listener_error, "mesh.rx.listener_error")
        except KeyError:
            pass
        if self._broadcast_thread and self._broadcast_thread.is_alive():
            self._broadcast_thread.join(timeout=2.0)

    def run_forever(self) -> None:
        self.start()
        try:
            while not self._stop.wait(1.0):
                pass
        finally:
            self.stop()

    def connect_send_socket(self) -> None:
        if getattr(conn, "socket", None) is None:
            conn.setup_multicast(self.config.udp.mcast_group, int(self.config.udp.mcast_port))

    def send_nodeinfo(self, destination: int = BROADCAST_NUM) -> int:
        user = mesh_pb2.User(
            id=self.config.node_id,
            long_name=self.config.long_name,
            short_name=self.config.short_name,
            hw_model=resolve_hw_model(self.config.hw_model),
        )
        user.role = resolve_role(self.config.role)
        if self._public_key_b64:
            user.public_key = b64_decode(self._public_key_b64)

        data = mesh_pb2.Data()
        data.portnum = portnums_pb2.PortNum.NODEINFO_APP
        data.payload = user.SerializeToString()
        data.source = self.node_num
        data.dest = int(destination)
        return self._send_data(data, destination=int(destination), force_pki=False)

    def send_text(
        self,
        destination: str | int,
        message: str,
        pki_mode: str = "auto",
        *,
        reply_id: int | None = None,
        emoji: bool = False,
        hop_limit: int | None = None,
        hop_start: int | None = None,
        want_ack: bool | None = None,
    ) -> int:
        destination_num = self._resolve_destination(destination)
        data = mesh_pb2.Data()
        data.portnum = portnums_pb2.PortNum.TEXT_MESSAGE_APP
        data.payload = message.encode("utf-8")
        data.source = self.node_num
        data.dest = destination_num
        if reply_id is not None:
            data.reply_id = int(reply_id)
        if emoji:
            data.emoji = 1

        use_pki = self._should_use_pki(destination_num, data.portnum, pki_mode)
        return self._send_data(
            data,
            destination=destination_num,
            force_pki=use_pki,
            hop_limit=hop_limit,
            hop_start=hop_start,
            want_ack=self._default_want_ack(destination_num) if want_ack is None else bool(want_ack),
        )

    def send_reply(
        self,
        destination: str | int,
        message: str,
        *,
        reply_id: int,
        emoji: bool = False,
        pki_mode: str = "auto",
        hop_limit: int | None = None,
        hop_start: int | None = None,
        want_ack: bool | None = None,
    ) -> int:
        return self.send_text(
            destination,
            message,
            pki_mode=pki_mode,
            reply_id=reply_id,
            emoji=emoji,
            hop_limit=hop_limit,
            hop_start=hop_start,
            want_ack=want_ack,
        )

    def is_direct_message_for_me(self, packet: mesh_pb2.MeshPacket) -> bool:
        return bool(
            int(getattr(packet, "to", BROADCAST_NUM)) == self.node_num
            and getattr(packet, "from", None) not in (None, self.node_num)
        )

    def is_text_message(self, packet: mesh_pb2.MeshPacket) -> bool:
        return bool(packet.HasField("decoded") and packet.decoded.portnum in TEXT_PORTNUMS)

    def get_text_message(self, packet: mesh_pb2.MeshPacket) -> str | None:
        if not self.is_text_message(packet):
            return None
        return packet.decoded.payload.decode("utf-8", "ignore")

    def reply_to_packet(
        self,
        packet: mesh_pb2.MeshPacket,
        message: str,
        *,
        emoji: bool = False,
        pki_mode: str = "auto",
        want_ack: bool | None = None,
    ) -> int:
        sender_id = getattr(packet, "from", None)
        if sender_id is None:
            raise ValueError("Packet does not have a sender")

        inbound_hop_limit = packet.hop_limit or self.config.hop_limit or 3
        inbound_hop_start = packet.hop_start or inbound_hop_limit
        return self.send_reply(
            int(sender_id),
            message,
            reply_id=int(getattr(packet, "id")),
            emoji=emoji,
            pki_mode=pki_mode,
            hop_limit=inbound_hop_limit,
            hop_start=inbound_hop_start,
            want_ack=want_ack,
        )

    def _send_data(
        self,
        data: mesh_pb2.Data,
        *,
        destination: int,
        force_pki: bool,
        hop_limit: int | None = None,
        hop_start: int | None = None,
        want_ack: bool = False,
    ) -> int:
        self.connect_send_socket()
        packet = mesh_pb2.MeshPacket()
        packet.id = self._next_packet_id()
        setattr(packet, "from", self.node_num)
        packet.to = int(destination)
        packet.want_ack = bool(want_ack)
        resolved_hop_limit = int(self.config.hop_limit if hop_limit is None else hop_limit)
        resolved_hop_start = int(resolved_hop_limit if hop_start is None else hop_start)
        if resolved_hop_start < resolved_hop_limit:
            resolved_hop_start = resolved_hop_limit
        packet.hop_limit = resolved_hop_limit
        packet.hop_start = resolved_hop_start

        if force_pki:
            remote_public_key = self._lookup_public_key(destination)
            if remote_public_key is None:
                raise ValueError(f"Destination {destination} does not have a stored public key in meshdb")
            packet.channel = 0
            packet.pki_encrypted = True
            packet.encrypted = encrypt_dm(
                sender_private_key=b64_decode(self.config.security.private_key),
                receiver_public_key=remote_public_key,
                packet_id=packet.id,
                from_node=self.node_num,
                plaintext=data.SerializeToString(),
            )
        else:
            packet.encrypted = mudp_encrypt_packet(
                self.config.channel.name,
                self.config.channel.psk,
                packet,
                data,
            )

        raw_packet = packet.SerializeToString()
        register_pending_ack(packet, raw_packet)
        conn.sendto(raw_packet, (conn.host, conn.port))
        return packet.id

    def _handle_raw_packet(self, packet: mesh_pb2.MeshPacket, addr: Any) -> None:
        if not getattr(packet, "rx_time", 0):
            packet.rx_time = int(time.time())

        if not packet.HasField("decoded"):
            self._try_decode_pki(packet)
        self._maybe_send_ack(packet)

    def _handle_unique_packet(self, packet: mesh_pb2.MeshPacket, addr: Any) -> None:
        del addr
        if not getattr(packet, "rx_time", 0):
            packet.rx_time = int(time.time())
        if not packet.HasField("decoded"):
            self._try_decode_pki(packet)

        normalized = meshdb.normalize_packet(packet, "udp")
        meshdb.handle_packet(
            normalized,
            node_database_number=self.node_num,
            db_path=self.meshdb_path,
        )

    def _handle_listener_error(self, error: Exception) -> None:
        raise RuntimeError("UDP listener failed") from error

    def _try_decode_pki(self, packet: mesh_pb2.MeshPacket) -> bool:
        if packet.channel != 0 or packet.to != self.node_num or not packet.encrypted:
            return False
        sender_public_key = self._lookup_public_key(getattr(packet, "from"))
        if sender_public_key is None:
            return False
        try:
            decrypted = decrypt_dm(
                receiver_private_key=b64_decode(self.config.security.private_key),
                sender_public_key=sender_public_key,
                packet_id=packet.id,
                from_node=getattr(packet, "from"),
                payload=bytes(packet.encrypted),
            )
            decoded = mesh_pb2.Data()
            decoded.ParseFromString(decrypted)
        except (ValueError, DecodeError):
            return False

        packet.decoded.CopyFrom(decoded)
        packet.pki_encrypted = True
        packet.public_key = sender_public_key
        return True

    def _maybe_send_ack(self, packet: mesh_pb2.MeshPacket) -> None:
        if not packet.HasField("decoded"):
            return
        if int(getattr(packet, "to", BROADCAST_NUM)) != self.node_num:
            return
        if not getattr(packet, "want_ack", False):
            return
        if is_ack(packet) or is_nak(packet):
            return
        ack_packet = send_ack(packet)
        publish_ack(ack_packet)

    def _broadcast_loop(self) -> None:
        interval = int(self.config.broadcasts.nodeinfo_interval_seconds)
        if interval <= 0:
            return
        while not self._stop.wait(interval):
            self.send_nodeinfo()

    def _resolve_destination(self, destination: str | int) -> int:
        if isinstance(destination, int):
            return destination
        text = str(destination).strip()
        if text.startswith("!"):
            return parse_node_id(text)
        resolved = meshdb.get_node_num(text, owner_node_num=self.node_num, db_path=self.meshdb_path)
        if isinstance(resolved, list):
            raise ValueError(f"Destination '{destination}' is ambiguous: {resolved}")
        if resolved is None:
            raise ValueError(f"Unknown destination '{destination}'")
        return int(resolved)

    def _lookup_public_key(self, node_num: int) -> bytes | None:
        if int(node_num) == self.node_num:
            key = self._public_key_b64
            return b64_decode(key) if key else None
        row = meshdb.get_nodeinfo(int(node_num), owner_node_num=self.node_num, db_path=self.meshdb_path)
        if not isinstance(row, dict):
            return None
        public_key = str(row.get("public_key", "")).strip()
        if not public_key:
            return None
        return b64_decode(public_key)

    def _should_use_pki(self, destination: int, portnum: int, pki_mode: str) -> bool:
        mode = pki_mode.strip().lower()
        if mode not in {"auto", "on", "off"}:
            raise ValueError("pki_mode must be one of: auto, on, off")
        if mode == "off":
            return False
        if destination == BROADCAST_NUM or portnum in PKI_DISALLOWED_PORTNUMS:
            if mode == "on":
                raise ValueError("Meshtastic PKI is only valid for direct messages on supported portnums")
            return False
        if mode == "on":
            return True
        return (
            not self.config.is_licensed
            and self._lookup_public_key(destination) is not None
        )

    def _default_want_ack(self, destination: int) -> bool:
        return int(destination) != BROADCAST_NUM

    def _next_packet_id(self) -> int:
        self._message_id = ((self._message_id + 1) % 1024) | (random.getrandbits(22) << 10)
        return self._message_id
