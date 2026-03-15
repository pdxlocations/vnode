from __future__ import annotations

import random
import sqlite3
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable, Dict, Optional, Union

import meshdb
from google.protobuf.json_format import MessageToDict
from google.protobuf.message import DecodeError
from meshtastic import BROADCAST_ADDR, BROADCAST_NUM, config_pb2, mesh_pb2, portnums_pb2
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
NODEINFO_REPLY_SUPPRESS_SECONDS = 12 * 60 * 60
POSITION_REPLY_THROTTLE_SECONDS = 3 * 60
NODEINFO_REPLY_BASE_SECONDS = 10 * 60
PRESET_THROTTLE_FACTORS = {
    "LONGFAST": 2048.0 / (250.0 * 100.0),
    "MEDIUMSLOW": 1024.0 / (250.0 * 100.0),
    "MEDIUMFAST": 512.0 / (250.0 * 100.0),
    "SHORTFAST": 128.0 / (250.0 * 100.0),
}


def parse_node_id(node_id: Union[str, int]) -> int:
    if isinstance(node_id, int):
        return node_id
    text = str(node_id).strip()
    if text.startswith("!"):
        text = text[1:]
    return int(text, 16)


def resolve_hw_model(value: Union[str, int]) -> int:
    if isinstance(value, int):
        return value
    return mesh_pb2.HardwareModel.Value(str(value))


def resolve_role(value: Union[str, int]) -> int:
    if isinstance(value, int):
        return value
    return config_pb2.Config.DeviceConfig.Role.Value(str(value))


class VirtualNode:
    RECEIVE_TOPIC = "mesh.rx.packet"
    PACKET_TOPIC = "mesh.rx.unique_packet"
    DUPLICATE_TOPIC = "mesh.rx.duplicate"

    def __init__(self, config_path: Union[str, Path] = "node.json") -> None:
        self.config_path = Path(config_path).resolve()
        self.base_dir = self.config_path.parent
        self.public_key_path = self.config_path.with_suffix(".public.key")
        self.config = NodeConfig.load(self.config_path)
        self.node_num = parse_node_id(self.config.node_id)
        self.role_num = resolve_role(self.config.role)
        self.meshdb_path = str((self.base_dir / self.config.meshdb.path).resolve())
        self.stream: Optional[UDPPacketStream] = None
        self._stop = threading.Event()
        self._broadcast_thread: Optional[threading.Thread] = None
        self._message_id = random.getrandbits(32)
        self._public_key_b64 = ""
        self._last_nodeinfo_sent_monotonic = 0.0
        self._last_position_reply_monotonic = 0.0
        self._last_nodeinfo_seen: Dict[int, int] = {}
        self._response_handlers: Dict[int, tuple[Callable[[Dict[str, Any]], Any], bool]] = {}
        self.nodesByNum: Dict[int, Dict[str, Any]] = {}
        self.nodes: Dict[str, Dict[str, Any]] = {}
        self.myInfo = SimpleNamespace(my_node_num=self.node_num)
        self._connected = False

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
        self._upsert_local_node_cache()

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
        self.stream = UDPPacketStream(
            self.config.udp.mcast_group,
            int(self.config.udp.mcast_port),
            key=self.config.channel.psk,
            parse_payload=False,
        )
        self.stream.start()
        self._connected = True
        self._publish_log_line(f"virtual node connected: {self.config.node_id}")
        pub.sendMessage("meshtastic.connection.established", interface=self)
        self._publish_node_updated(self.nodesByNum[self.node_num])
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
        was_connected = self._connected
        self._connected = False
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
        if self._broadcast_thread and self._broadcast_thread.is_alive():
            self._broadcast_thread.join(timeout=2.0)
        if was_connected:
            self._publish_log_line(f"virtual node disconnected: {self.config.node_id}")
            pub.sendMessage("meshtastic.connection.lost", interface=self)

    def run_forever(self) -> None:
        self.start()
        try:
            while not self._stop.wait(1.0):
                pass
        finally:
            self.stop()

    def receive(self, callback: Callable[..., Any]) -> None:
        pub.subscribe(callback, "meshtastic.receive")

    def unreceive(self, callback: Callable[..., Any]) -> None:
        try:
            pub.unsubscribe(callback, "meshtastic.receive")
        except KeyError:
            pass

    def close(self) -> None:
        self.stop()

    def sendText(
        self,
        text: str,
        destinationId: Union[int, str] = BROADCAST_ADDR,
        wantAck: bool = False,
        wantResponse: bool = False,
        onResponse: Optional[Callable[[dict], Any]] = None,
        channelIndex: int = 0,
        portNum: int = portnums_pb2.PortNum.TEXT_MESSAGE_APP,
        replyId: Optional[int] = None,
        hopLimit: Optional[int] = None,
    ) -> mesh_pb2.MeshPacket:
        return self.sendData(
            text.encode("utf-8"),
            destinationId=destinationId,
            portNum=portNum,
            wantAck=wantAck,
            wantResponse=wantResponse,
            onResponse=onResponse,
            channelIndex=channelIndex,
            hopLimit=hopLimit,
            replyId=replyId,
        )

    def sendData(
        self,
        data: Any,
        destinationId: Union[int, str] = BROADCAST_ADDR,
        portNum: int = portnums_pb2.PortNum.PRIVATE_APP,
        wantAck: bool = False,
        wantResponse: bool = False,
        onResponse: Optional[Callable[[dict], Any]] = None,
        onResponseAckPermitted: bool = False,
        channelIndex: int = 0,
        hopLimit: Optional[int] = None,
        pkiEncrypted: bool = False,
        publicKey: Optional[bytes] = None,
        priority: int = mesh_pb2.MeshPacket.Priority.RELIABLE,
        replyId: Optional[int] = None,
    ) -> mesh_pb2.MeshPacket:
        if channelIndex != 0:
            raise ValueError("vnode currently supports only channelIndex=0")
        if getattr(data, "SerializeToString", None):
            data = data.SerializeToString()
        payload = bytes(data)
        destination_num = self._resolve_destination(destinationId)

        decoded = mesh_pb2.Data()
        decoded.portnum = int(portNum)
        decoded.payload = payload
        decoded.source = self.node_num
        decoded.dest = destination_num
        decoded.want_response = bool(wantResponse)
        if replyId is not None:
            decoded.reply_id = int(replyId)

        packet = self._send_packet(
            decoded,
            destination=destination_num,
            force_pki=bool(pkiEncrypted),
            hop_limit=hopLimit,
            hop_start=None,
            want_ack=bool(wantAck),
            priority=priority,
            remote_public_key=publicKey,
        )
        if onResponse is not None:
            self._response_handlers[int(packet.id)] = (onResponse, bool(onResponseAckPermitted))
        return self._packet_for_return(packet, decoded)

    def sendPosition(
        self,
        latitude: float = 0.0,
        longitude: float = 0.0,
        altitude: int = 0,
        destinationId: Union[int, str] = BROADCAST_ADDR,
        wantAck: bool = False,
        wantResponse: bool = False,
        channelIndex: int = 0,
        hopLimit: Optional[int] = None,
    ) -> mesh_pb2.MeshPacket:
        position = mesh_pb2.Position()
        if latitude != 0.0:
            position.latitude_i = int(latitude / 1e-7)
        if longitude != 0.0:
            position.longitude_i = int(longitude / 1e-7)
        if altitude != 0:
            position.altitude = int(altitude)
        return self.sendData(
            position,
            destinationId=destinationId,
            portNum=portnums_pb2.PortNum.POSITION_APP,
            wantAck=wantAck,
            wantResponse=wantResponse,
            channelIndex=channelIndex,
            hopLimit=hopLimit,
        )

    def getMyNodeInfo(self) -> Optional[Dict[str, Any]]:
        return self.nodesByNum.get(self.node_num)

    def getMyUser(self) -> Optional[Dict[str, Any]]:
        node_info = self.getMyNodeInfo()
        if node_info is None:
            return None
        user = node_info.get("user")
        return user if isinstance(user, dict) else None

    def getLongName(self) -> Optional[str]:
        user = self.getMyUser()
        if user is None:
            return None
        value = user.get("longName")
        return str(value) if value is not None else None

    def connect_send_socket(self) -> None:
        if getattr(conn, "socket", None) is None:
            conn.setup_multicast(self.config.udp.mcast_group, int(self.config.udp.mcast_port))

    def send_nodeinfo(self, destination: int = BROADCAST_NUM) -> int:
        return self._send_nodeinfo(destination)

    def _send_nodeinfo(
        self,
        destination: int = BROADCAST_NUM,
        *,
        request_id: Optional[int] = None,
        want_ack: bool = False,
    ) -> int:
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
        if request_id is not None:
            data.request_id = int(request_id)
        packet_id = self._send_data(
            data,
            destination=int(destination),
            force_pki=False,
            want_ack=want_ack,
        )
        self._last_nodeinfo_sent_monotonic = time.monotonic()
        return packet_id

    def send_position(
        self,
        destination: int = BROADCAST_NUM,
        *,
        latitude: Optional[float] = None,
        longitude: Optional[float] = None,
        altitude: Optional[int] = None,
    ) -> int:
        return self._send_position(
            destination,
            latitude=latitude,
            longitude=longitude,
            altitude=altitude,
        )

    def _send_position(
        self,
        destination: int = BROADCAST_NUM,
        *,
        latitude: Optional[float] = None,
        longitude: Optional[float] = None,
        altitude: Optional[int] = None,
        request_id: Optional[int] = None,
        want_ack: bool = False,
    ) -> int:
        if not self.config.position.enabled:
            raise ValueError("Position sending is disabled in node.json")
        resolved_latitude = self.config.position.latitude if latitude is None else latitude
        resolved_longitude = self.config.position.longitude if longitude is None else longitude
        resolved_altitude = self.config.position.altitude if altitude is None else altitude
        if resolved_latitude is None or resolved_longitude is None:
            raise ValueError("Position latitude and longitude must be configured before sending position")

        position = mesh_pb2.Position(
            latitude_i=int(float(resolved_latitude) * 1e7),
            longitude_i=int(float(resolved_longitude) * 1e7),
            time=int(time.time()),
        )
        if resolved_altitude is not None:
            position.altitude = int(resolved_altitude)
        data = mesh_pb2.Data()
        data.portnum = portnums_pb2.PortNum.POSITION_APP
        data.payload = position.SerializeToString()
        data.source = self.node_num
        data.dest = int(destination)
        if request_id is not None:
            data.request_id = int(request_id)
        return self._send_data(
            data,
            destination=int(destination),
            force_pki=False,
            want_ack=want_ack,
        )

    def send_text(
        self,
        destination: Union[str, int],
        message: str,
        pki_mode: str = "auto",
        *,
        reply_id: Optional[int] = None,
        emoji: bool = False,
        hop_limit: Optional[int] = None,
        hop_start: Optional[int] = None,
        want_ack: Optional[bool] = None,
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
        destination: Union[str, int],
        message: str,
        *,
        reply_id: int,
        emoji: bool = False,
        pki_mode: str = "auto",
        hop_limit: Optional[int] = None,
        hop_start: Optional[int] = None,
        want_ack: Optional[bool] = None,
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

    def get_text_message(self, packet: mesh_pb2.MeshPacket) -> Optional[str]:
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
        want_ack: Optional[bool] = None,
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
        hop_limit: Optional[int] = None,
        hop_start: Optional[int] = None,
        want_ack: bool = False,
    ) -> int:
        packet = self._send_packet(
            data,
            destination=destination,
            force_pki=force_pki,
            hop_limit=hop_limit,
            hop_start=hop_start,
            want_ack=want_ack,
        )
        return packet.id

    def _send_packet(
        self,
        data: mesh_pb2.Data,
        *,
        destination: int,
        force_pki: bool,
        hop_limit: Optional[int] = None,
        hop_start: Optional[int] = None,
        want_ack: bool = False,
        priority: Optional[int] = None,
        remote_public_key: Optional[bytes] = None,
    ) -> mesh_pb2.MeshPacket:
        self.connect_send_socket()
        packet = mesh_pb2.MeshPacket()
        packet.id = self._next_packet_id()
        setattr(packet, "from", self.node_num)
        packet.to = int(destination)
        packet.want_ack = bool(want_ack)
        if priority is not None:
            packet.priority = int(priority)
        resolved_hop_limit = int(self.config.hop_limit if hop_limit is None else hop_limit)
        resolved_hop_start = int(resolved_hop_limit if hop_start is None else hop_start)
        if resolved_hop_start < resolved_hop_limit:
            resolved_hop_start = resolved_hop_limit
        packet.hop_limit = resolved_hop_limit
        packet.hop_start = resolved_hop_start

        if force_pki:
            key_bytes = remote_public_key if remote_public_key is not None else self._lookup_public_key(destination)
            if key_bytes is None:
                raise ValueError(f"Destination {destination} does not have a stored public key in meshdb")
            packet.channel = 0
            packet.pki_encrypted = True
            packet.public_key = key_bytes
            packet.encrypted = encrypt_dm(
                sender_private_key=b64_decode(self.config.security.private_key),
                receiver_public_key=key_bytes,
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
        self._persist_outbound_packet(packet, data)
        return packet

    def _handle_raw_packet(self, packet: mesh_pb2.MeshPacket, **kwargs: Any) -> None:
        del kwargs
        if not getattr(packet, "rx_time", 0):
            packet.rx_time = int(time.time())

        if not packet.HasField("decoded"):
            self._try_decode_pki(packet)
        self._publish_meshtastic_receive(packet)
        self._maybe_send_ack(packet)
        self._maybe_send_response(packet)

    def _handle_unique_packet(self, packet: mesh_pb2.MeshPacket, **kwargs: Any) -> None:
        del kwargs
        if not getattr(packet, "rx_time", 0):
            packet.rx_time = int(time.time())
        if not packet.HasField("decoded"):
            self._try_decode_pki(packet)
        if getattr(packet, "from", None) == self.node_num:
            return

        self._persist_packet(packet)
        self._update_node_cache_from_packet(packet)

    def _packet_to_receive_dict(self, packet: mesh_pb2.MeshPacket) -> Dict[str, Any]:
        as_dict = MessageToDict(packet)
        as_dict["raw"] = packet

        if "from" not in as_dict:
            as_dict["from"] = 0
        if "to" not in as_dict:
            as_dict["to"] = 0

        as_dict["fromId"] = self._node_num_to_id(int(as_dict["from"]), is_dest=False)
        as_dict["toId"] = self._node_num_to_id(int(as_dict["to"]), is_dest=True)

        if "decoded" in as_dict and packet.HasField("decoded"):
            as_dict["decoded"]["payload"] = packet.decoded.payload
            if packet.decoded.portnum in TEXT_PORTNUMS:
                as_dict["decoded"]["text"] = packet.decoded.payload.decode("utf-8", "ignore")
            elif packet.decoded.portnum == portnums_pb2.PortNum.POSITION_APP:
                position = mesh_pb2.Position()
                try:
                    position.ParseFromString(packet.decoded.payload)
                    position_dict = MessageToDict(position)
                    position_dict["raw"] = position
                    as_dict["decoded"]["position"] = position_dict
                except DecodeError:
                    pass
            elif packet.decoded.portnum == portnums_pb2.PortNum.NODEINFO_APP:
                user = mesh_pb2.User()
                try:
                    user.ParseFromString(packet.decoded.payload)
                    user_dict = MessageToDict(user)
                    user_dict["raw"] = user
                    as_dict["decoded"]["user"] = user_dict
                except DecodeError:
                    pass

        return as_dict

    def _node_num_to_id(self, node_num: int, *, is_dest: bool) -> Optional[str]:
        if node_num == BROADCAST_NUM:
            return "^all" if is_dest else "Unknown"
        if node_num == self.node_num:
            return self.config.node_id

        return f"!{int(node_num):08x}"

    def _packet_for_return(self, packet: mesh_pb2.MeshPacket, data: mesh_pb2.Data) -> mesh_pb2.MeshPacket:
        returned = mesh_pb2.MeshPacket()
        returned.CopyFrom(packet)
        returned.decoded.CopyFrom(data)
        return returned

    def _publish_meshtastic_receive(self, packet: mesh_pb2.MeshPacket) -> None:
        if int(getattr(packet, "from", 0) or 0) == self.node_num:
            return
        packet_dict = self._packet_to_receive_dict(packet)
        self._dispatch_response_handler(packet, packet_dict)
        topic = "meshtastic.receive"
        if packet.HasField("decoded"):
            portnum_name = str(packet_dict.get("decoded", {}).get("portnum", "UNKNOWN_APP"))
            topic = f"meshtastic.receive.data.{portnum_name}"
            if packet.decoded.portnum in TEXT_PORTNUMS:
                topic = "meshtastic.receive.text"
            elif packet.decoded.portnum == portnums_pb2.PortNum.POSITION_APP:
                topic = "meshtastic.receive.position"
            elif packet.decoded.portnum == portnums_pb2.PortNum.NODEINFO_APP:
                topic = "meshtastic.receive.user"
        pub.sendMessage(topic, packet=packet_dict, interface=self)

    def _dispatch_response_handler(self, packet: mesh_pb2.MeshPacket, packet_dict: Dict[str, Any]) -> None:
        decoded = packet_dict.get("decoded")
        if not isinstance(decoded, dict):
            return
        request_id = decoded.get("requestId")
        if request_id is None:
            return
        try:
            request_id_num = int(request_id)
        except (TypeError, ValueError):
            return
        handler = self._response_handlers.get(request_id_num)
        if handler is None:
            return
        callback, ack_permitted = handler
        if is_ack(packet) and not ack_permitted and getattr(callback, "__name__", "") != "onAckNak":
            return
        self._response_handlers.pop(request_id_num, None)
        callback(packet_dict)

    def _upsert_local_node_cache(self) -> None:
        node = self._default_node_dict(self.node_num)
        node["user"].update(
            {
                "id": self.config.node_id,
                "longName": self.config.long_name,
                "shortName": self.config.short_name,
                "hwModel": str(self.config.hw_model),
                "role": str(self.config.role),
                "publicKey": self._public_key_b64,
                "isLicensed": bool(self.config.is_licensed),
            }
        )
        if (
            self.config.position.enabled
            and self.config.position.latitude is not None
            and self.config.position.longitude is not None
        ):
            node["position"] = {
                "latitudeI": int(float(self.config.position.latitude) * 1e7),
                "longitudeI": int(float(self.config.position.longitude) * 1e7),
            }
            if self.config.position.altitude is not None:
                node["position"]["altitude"] = int(self.config.position.altitude)
        self.nodesByNum[self.node_num] = node
        self.nodes[self.config.node_id] = node

    def _default_node_dict(self, node_num: int) -> Dict[str, Any]:
        node_id = f"!{int(node_num):08x}"
        return {
            "num": int(node_num),
            "user": {
                "id": node_id,
                "longName": f"Meshtastic {node_id[-4:]}",
                "shortName": node_id[-4:],
                "hwModel": "UNSET",
            },
        }

    def _update_node_cache_from_packet(self, packet: mesh_pb2.MeshPacket) -> None:
        sender = int(getattr(packet, "from", 0) or 0)
        if sender == 0:
            return
        packet_dict = self._packet_to_receive_dict(packet)
        node = dict(self.nodesByNum.get(sender, self._default_node_dict(sender)))
        changed = sender not in self.nodesByNum

        rx_time = packet_dict.get("rxTime")
        if rx_time is not None and node.get("lastHeard") != rx_time:
            node["lastHeard"] = rx_time
            changed = True
        snr = packet_dict.get("rxSnr")
        if snr is not None and node.get("snr") != snr:
            node["snr"] = snr
            changed = True

        decoded = packet_dict.get("decoded")
        if isinstance(decoded, dict):
            user = decoded.get("user")
            if isinstance(user, dict):
                clean_user = dict(user)
                clean_user.pop("raw", None)
                existing_user = node.get("user", {})
                merged_user = dict(existing_user) if isinstance(existing_user, dict) else {}
                merged_user.update(clean_user)
                if merged_user != existing_user:
                    node["user"] = merged_user
                    changed = True
            position = decoded.get("position")
            if isinstance(position, dict):
                clean_position = dict(position)
                clean_position.pop("raw", None)
                if clean_position != node.get("position"):
                    node["position"] = clean_position
                    changed = True

        self.nodesByNum[sender] = node
        user = node.get("user")
        if isinstance(user, dict):
            node_id = user.get("id")
            if node_id:
                self.nodes[str(node_id)] = node
        if changed:
            self._publish_node_updated(node)

    def _publish_node_updated(self, node: Dict[str, Any]) -> None:
        pub.sendMessage("meshtastic.node.updated", node=node, interface=self)

    def _publish_log_line(self, line: str) -> None:
        pub.sendMessage("meshtastic.log.line", line=str(line), interface=self)

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

    def _maybe_send_response(self, packet: mesh_pb2.MeshPacket) -> None:
        if not packet.HasField("decoded"):
            return
        if int(getattr(packet, "to", BROADCAST_NUM)) != self.node_num:
            return
        if getattr(packet, "from", None) in (None, self.node_num):
            return
        if not getattr(packet.decoded, "want_response", False):
            return

        destination = int(getattr(packet, "from"))
        request_id = int(getattr(packet, "id"))
        want_ack = bool(getattr(packet, "want_ack", False))

        if packet.decoded.portnum == portnums_pb2.PortNum.NODEINFO_APP:
            if self._should_ignore_nodeinfo_response(packet):
                return
            self._send_nodeinfo(destination, request_id=request_id, want_ack=want_ack)
            return

        if packet.decoded.portnum == portnums_pb2.PortNum.POSITION_APP:
            if self._should_ignore_position_response():
                return
            if self.config.position.enabled and self.config.position.latitude is not None and self.config.position.longitude is not None:
                self._send_position(destination, request_id=request_id, want_ack=want_ack)
                self._last_position_reply_monotonic = time.monotonic()
            else:
                publish_ack(send_ack(packet, error_reason=mesh_pb2.Routing.Error.NO_RESPONSE))
            return

        publish_ack(send_ack(packet, error_reason=mesh_pb2.Routing.Error.NO_RESPONSE))

    def _should_ignore_nodeinfo_response(self, packet: mesh_pb2.MeshPacket) -> bool:
        sender = int(getattr(packet, "from"))
        now = int(getattr(packet, "rx_time", 0) or time.time())
        last_seen = self._last_nodeinfo_seen.get(sender)
        self._last_nodeinfo_seen[sender] = now
        self._prune_nodeinfo_cache()
        if last_seen is not None:
            since_last = now - last_seen if now >= last_seen else 0
            if since_last < NODEINFO_REPLY_SUPPRESS_SECONDS:
                return True

        timeout_seconds = self._nodeinfo_reply_timeout_seconds()
        if self._last_nodeinfo_sent_monotonic and (time.monotonic() - self._last_nodeinfo_sent_monotonic) < timeout_seconds:
            return True
        return False

    def _should_ignore_position_response(self) -> bool:
        return bool(
            self.role_num != config_pb2.Config.DeviceConfig.Role.LOST_AND_FOUND
            and self._last_position_reply_monotonic
            and (time.monotonic() - self._last_position_reply_monotonic) < POSITION_REPLY_THROTTLE_SECONDS
        )

    def _nodeinfo_reply_timeout_seconds(self) -> float:
        non_scaling_roles = {
            config_pb2.Config.DeviceConfig.Role.ROUTER,
            config_pb2.Config.DeviceConfig.Role.ROUTER_LATE,
            config_pb2.Config.DeviceConfig.Role.SENSOR,
            config_pb2.Config.DeviceConfig.Role.TRACKER,
            config_pb2.Config.DeviceConfig.Role.TAK_TRACKER,
        }
        if self.role_num in non_scaling_roles:
            return float(NODEINFO_REPLY_BASE_SECONDS)

        known_nodes = self._known_node_count()
        if known_nodes <= 40:
            return float(NODEINFO_REPLY_BASE_SECONDS)
        factor = PRESET_THROTTLE_FACTORS.get(self.config.channel.name.strip().upper(), PRESET_THROTTLE_FACTORS["LONGFAST"])
        return float(NODEINFO_REPLY_BASE_SECONDS) * (1.0 + ((known_nodes - 40) * factor))

    def _known_node_count(self) -> int:
        try:
            node_db = meshdb.NodeDB(self.node_num, self.meshdb_path)
            node_db.ensure_table()
            with node_db.connect() as con:
                row = con.execute(f"SELECT COUNT(*) FROM {node_db.table}").fetchone()
            return max(int(row[0]) if row else 0, 1)
        except (sqlite3.Error, ValueError, TypeError):
            return max(len(self._last_nodeinfo_seen), 1)

    def _prune_nodeinfo_cache(self) -> None:
        max_entries = self._known_node_count()
        while self._last_nodeinfo_seen and len(self._last_nodeinfo_seen) > max_entries:
            oldest_sender = min(self._last_nodeinfo_seen, key=self._last_nodeinfo_seen.get)
            self._last_nodeinfo_seen.pop(oldest_sender, None)

    def _persist_outbound_packet(self, packet: mesh_pb2.MeshPacket, data: mesh_pb2.Data) -> None:
        stored_packet = mesh_pb2.MeshPacket()
        stored_packet.CopyFrom(packet)
        stored_packet.rx_time = int(time.time())
        stored_packet.transport_mechanism = mesh_pb2.MeshPacket.TransportMechanism.TRANSPORT_MULTICAST_UDP
        stored_packet.decoded.CopyFrom(data)
        self._persist_packet(stored_packet)

    def _persist_packet(self, packet: mesh_pb2.MeshPacket) -> None:
        normalized = meshdb.normalize_packet(packet, "udp")
        meshdb.handle_packet(
            normalized,
            node_database_number=self.node_num,
            db_path=self.meshdb_path,
        )

    def _broadcast_loop(self) -> None:
        nodeinfo_interval = int(self.config.broadcasts.nodeinfo_interval_seconds)
        position_interval = int(self.config.position.position_interval_seconds)
        have_position = (
            self.config.position.enabled
            and self.config.position.latitude is not None
            and self.config.position.longitude is not None
        )
        if nodeinfo_interval <= 0 and (position_interval <= 0 or not have_position):
            return
        next_nodeinfo = time.monotonic() + max(nodeinfo_interval, 0) if nodeinfo_interval > 0 else None
        next_position = time.monotonic() + max(position_interval, 0) if position_interval > 0 and have_position else None

        while not self._stop.is_set():
            due_times = [due for due in (next_nodeinfo, next_position) if due is not None]
            if not due_times:
                return
            wait_seconds = max(min(due_times) - time.monotonic(), 0.0)
            if self._stop.wait(wait_seconds):
                return

            now = time.monotonic()
            if next_nodeinfo is not None and now >= next_nodeinfo:
                self.send_nodeinfo()
                next_nodeinfo = now + nodeinfo_interval
            if next_position is not None and now >= next_position:
                self.send_position()
                next_position = now + position_interval

    def _resolve_destination(self, destination: Union[str, int]) -> int:
        if isinstance(destination, int):
            return destination
        text = str(destination).strip()
        if text == BROADCAST_ADDR:
            return BROADCAST_NUM
        if text.startswith("!"):
            return parse_node_id(text)
        resolved = meshdb.get_node_num(text, owner_node_num=self.node_num, db_path=self.meshdb_path)
        if isinstance(resolved, list):
            raise ValueError(f"Destination '{destination}' is ambiguous: {resolved}")
        if resolved is None:
            raise ValueError(f"Unknown destination '{destination}'")
        return int(resolved)

    def _lookup_public_key(self, node_num: int) -> Optional[bytes]:
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
