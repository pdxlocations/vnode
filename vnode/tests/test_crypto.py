import unittest
import json
import sqlite3
import sys
import tempfile
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE_ROOT = REPO_ROOT / "vnode"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from meshtastic import BROADCAST_NUM
from examples.autoresponder import DirectMessageAutoResponder
from meshdb import NodeDB, handle_packet, normalize_packet
from pubsub import pub
from meshtastic.protobuf import mesh_pb2, portnums_pb2
from mudp import UDPPacketStream, build_mesh_packet
from mudp import send_text_message as mudp_send_text_message
from mudp.encryption import decrypt_packet as decrypt_channel_packet
from mudp.reliability import NUM_RELIABLE_RETX, pending_acks
from mudp.singleton import conn
from vnode.crypto import (
    b64_encode,
    build_nonce,
    build_shared_key,
    decrypt_dm,
    derive_public_key,
    encrypt_dm,
    generate_keypair,
)
from vnode.runtime import VirtualNode


class PkiCryptoTest(unittest.TestCase):
    def setUp(self) -> None:
        pending_acks.clear()

    def tearDown(self) -> None:
        pending_acks.clear()

    def _write_temp_config(self, root: Path, private_key_b64: str) -> Path:
        config_path = root / "node.json"
        data_dir = root / "data"
        config_path.write_text(
            json.dumps(
                {
                    "node_id": "!89abcdef",
                    "long_name": "Virtual Meshtastic Node",
                    "short_name": "VND",
                    "hw_model": "ANDROID_SIM",
                    "role": "CLIENT",
                    "is_licensed": False,
                    "hop_limit": 3,
                    "broadcasts": {
                        "send_startup_nodeinfo": False,
                        "nodeinfo_interval_seconds": 900,
                    },
                    "position": {
                        "enabled": False,
                        "latitude": None,
                        "longitude": None,
                        "altitude": None,
                        "position_interval_seconds": 900,
                    },
                    "channel": {
                        "name": "LongFast",
                        "psk": "AQ==",
                    },
                    "udp": {
                        "mcast_group": "224.0.0.69",
                        "mcast_port": 4403,
                    },
                    "meshdb": {
                        "path": str(data_dir),
                    },
                    "security": {
                        "private_key": private_key_b64,
                    },
                }
            ),
            encoding="utf-8",
        )
        return config_path

    def test_nonce_matches_firmware_layout(self) -> None:
        nonce = build_nonce(0x13B2D662, 0x0929, 0x2B796A03)
        self.assertEqual(nonce.hex(), "62d6b213036a792b2909000000")

    def test_shared_key_matches_firmware_vector_prefix(self) -> None:
        private_key = bytes.fromhex("a00330633e63522f8a4d81ec6d9d1e6617f6c8ffd3a4c698229537d44e522277")
        public_key = bytes.fromhex("db18fc50eea47f00251cb784819a3cf5fc361882597f589f0d7ff820e8064457")
        shared_key = build_shared_key(private_key, public_key)
        self.assertEqual(shared_key[:8].hex(), "777b1545c9d6f9a2")

    def test_decrypts_firmware_vector(self) -> None:
        private_key = bytes.fromhex("a00330633e63522f8a4d81ec6d9d1e6617f6c8ffd3a4c698229537d44e522277")
        public_key = bytes.fromhex("db18fc50eea47f00251cb784819a3cf5fc361882597f589f0d7ff820e8064457")
        payload = bytes.fromhex("40df24abfcc30a17a3d9046726099e796a1c036a792b")
        decrypted = decrypt_dm(
            receiver_private_key=private_key,
            sender_public_key=public_key,
            packet_id=0x13B2D662,
            from_node=0x0929,
            payload=payload,
        )
        self.assertEqual(decrypted.hex(), "08011204746573744800")

    def test_round_trip(self) -> None:
        sender_private = bytes.fromhex("a00330633e63522f8a4d81ec6d9d1e6617f6c8ffd3a4c698229537d44e522277")
        receiver_private = bytes.fromhex("c0f2fa9bb9b22cf3d8d5bb4246cc8d4783e924166a4630bf8c1ad7af5120e648")
        sender_public = derive_public_key(sender_private)
        receiver_public = derive_public_key(receiver_private)
        plaintext = b"hello mesh"

        encrypted = encrypt_dm(
            sender_private_key=sender_private,
            receiver_public_key=receiver_public,
            packet_id=123,
            from_node=456,
            plaintext=plaintext,
            extra_nonce=789,
        )
        decrypted = decrypt_dm(
            receiver_private_key=receiver_private,
            sender_public_key=sender_public,
            packet_id=123,
            from_node=456,
            payload=encrypted,
        )
        self.assertEqual(decrypted, plaintext)

    def test_private_key_change_updates_generated_public_key_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _public_a, private_a = generate_keypair()
            expected_public_b, private_b = generate_keypair()

            config_path = self._write_temp_config(root, b64_encode(private_a))

            VirtualNode(config_path)
            public_key_path = root / "node.public.key"
            first_public = public_key_path.read_text(encoding="utf-8").strip()

            payload = json.loads(config_path.read_text(encoding="utf-8"))
            payload["security"]["private_key"] = b64_encode(private_b)
            config_path.write_text(json.dumps(payload), encoding="utf-8")

            VirtualNode(config_path)
            second_public = public_key_path.read_text(encoding="utf-8").strip()

            self.assertNotEqual(first_public, second_public)
            self.assertEqual(second_public, b64_encode(expected_public_b))

    def test_missing_node_json_is_created_from_example_template(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config_path = root / "node.json"
            example_path = root / "example-node.json"
            example_path.write_text(
                json.dumps(
                    {
                        "node_id": "",
                        "long_name": "",
                        "short_name": "",
                        "hw_model": "ANDROID_SIM",
                        "role": "CLIENT",
                        "is_licensed": False,
                        "hop_limit": 5,
                        "broadcasts": {
                            "send_startup_nodeinfo": False,
                            "nodeinfo_interval_seconds": 120,
                        },
                        "position": {
                            "enabled": True,
                            "latitude": 45.523064,
                            "longitude": -122.676483,
                            "altitude": 27,
                            "position_interval_seconds": 300,
                        },
                        "channel": {
                            "name": "TemplateChannel",
                            "psk": "AQ==",
                        },
                        "udp": {
                            "mcast_group": "224.0.0.69",
                            "mcast_port": 4403,
                        },
                        "meshdb": {
                            "path": "./data",
                        },
                        "security": {
                            "private_key": "",
                        },
                    }
                ),
                encoding="utf-8",
            )

            node = VirtualNode(config_path)
            written = json.loads(config_path.read_text(encoding="utf-8"))

            self.assertTrue(config_path.exists())
            self.assertRegex(node.config.node_id, r"^![0-9a-f]{8}$")
            expected_suffix = node.config.node_id[-4:]
            self.assertEqual(node.config.long_name, f"Meshtastic {expected_suffix}")
            self.assertEqual(node.config.short_name, expected_suffix)
            self.assertEqual(node.config.channel.name, "TemplateChannel")
            self.assertEqual(node.config.hop_limit, 5)
            self.assertTrue(node.config.position.enabled)
            self.assertEqual(node.config.position.latitude, 45.523064)
            self.assertEqual(node.config.position.longitude, -122.676483)
            self.assertEqual(node.config.position.altitude, 27)
            self.assertEqual(written["node_id"], node.config.node_id)
            self.assertEqual(written["long_name"], f"Meshtastic {expected_suffix}")
            self.assertEqual(written["short_name"], expected_suffix)
            self.assertTrue(written["security"]["private_key"])

    def test_send_position_uses_configured_lat_lon(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _public_key, private_key = generate_keypair()
            config_path = self._write_temp_config(root, b64_encode(private_key))
            payload = json.loads(config_path.read_text(encoding="utf-8"))
            payload["position"] = {
                "enabled": True,
                "latitude": 45.523064,
                "longitude": -122.676483,
                "altitude": 27,
                "position_interval_seconds": 900,
            }
            config_path.write_text(json.dumps(payload), encoding="utf-8")
            node = VirtualNode(config_path)

            sent: list[bytes] = []
            original_sendto = conn.sendto
            original_host = conn.host
            original_port = conn.port
            try:
                node.connect_send_socket = lambda: None
                conn.host = "224.0.0.69"
                conn.port = 4403
                conn.sendto = lambda data, addr: sent.append(data)
                packet_id = node.send_position()
            finally:
                conn.sendto = original_sendto
                conn.host = original_host
                conn.port = original_port

            self.assertEqual(len(sent), 1)
            packet = mesh_pb2.MeshPacket()
            packet.ParseFromString(sent[0])
            self.assertEqual(packet.id, packet_id)
            decoded = decrypt_channel_packet(packet, node.config.channel.psk)
            self.assertIsNotNone(decoded)
            self.assertEqual(decoded.portnum, portnums_pb2.PortNum.POSITION_APP)
            position = mesh_pb2.Position()
            position.ParseFromString(decoded.payload)
            self.assertEqual(position.latitude_i, int(45.523064 * 1e7))
            self.assertEqual(position.longitude_i, int(-122.676483 * 1e7))
            self.assertEqual(position.altitude, 27)

    def test_send_position_requires_enabled_flag(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _public_key, private_key = generate_keypair()
            config_path = self._write_temp_config(root, b64_encode(private_key))
            payload = json.loads(config_path.read_text(encoding="utf-8"))
            payload["position"] = {
                "enabled": False,
                "latitude": 45.523064,
                "longitude": -122.676483,
                "altitude": 27,
                "position_interval_seconds": 900,
            }
            config_path.write_text(json.dumps(payload), encoding="utf-8")
            node = VirtualNode(config_path)

            with self.assertRaisesRegex(ValueError, "disabled"):
                node.send_position()

    def test_direct_text_messages_request_ack_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _public_key, private_key = generate_keypair()
            config_path = self._write_temp_config(root, b64_encode(private_key))
            node = VirtualNode(config_path)

            sent: list[bytes] = []
            original_sendto = conn.sendto
            original_host = conn.host
            original_port = conn.port
            try:
                node.connect_send_socket = lambda: None
                conn.host = "224.0.0.69"
                conn.port = 4403
                conn.sendto = lambda data, addr: sent.append(data)
                packet_id = node.send_text("!12345678", "hello")
            finally:
                conn.sendto = original_sendto
                conn.host = original_host
                conn.port = original_port

            self.assertEqual(len(sent), 1)
            packet = mesh_pb2.MeshPacket()
            packet.ParseFromString(sent[0])
            self.assertEqual(packet.id, packet_id)
            self.assertTrue(packet.want_ack)
            self.assertEqual(packet.to, int("12345678", 16))
            pending = pending_acks.get(packet_id)
            self.assertIsNotNone(pending)
            self.assertEqual(pending.destination, int("12345678", 16))
            self.assertGreater(pending.next_retry_monotonic, time.monotonic())

    def test_outgoing_channel_text_message_is_saved_to_meshdb(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _public_key, private_key = generate_keypair()
            config_path = self._write_temp_config(root, b64_encode(private_key))
            node = VirtualNode(config_path)

            sent: list[bytes] = []
            original_sendto = conn.sendto
            original_host = conn.host
            original_port = conn.port
            try:
                node.connect_send_socket = lambda: None
                conn.host = "224.0.0.69"
                conn.port = 4403
                conn.sendto = lambda data, addr: sent.append(data)
                packet_id = node.send_text("!12345678", "store outbound")
            finally:
                conn.sendto = original_sendto
                conn.host = original_host
                conn.port = original_port

            self.assertEqual(len(sent), 1)
            packet = mesh_pb2.MeshPacket()
            packet.ParseFromString(sent[0])
            self.assertEqual(packet.id, packet_id)

            with sqlite3.connect(Path(node.meshdb_path) / f"{node.node_num}.db") as con:
                row = con.execute(
                    f'SELECT node_num, message_text, packet_id, to_node, channel, want_ack, pki_encrypted '
                    f'FROM "{node.node_num}_{packet.channel}_messages" WHERE packet_id = ?',
                    (packet_id,),
                ).fetchone()

            self.assertEqual(
                row,
                (
                    str(node.node_num),
                    "store outbound",
                    packet_id,
                    int("12345678", 16),
                    packet.channel,
                    1,
                    0,
                ),
            )

    def test_outgoing_pki_text_message_is_saved_to_meshdb(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _public_key, private_key = generate_keypair()
            peer_public_key, _peer_private_key = generate_keypair()
            config_path = self._write_temp_config(root, b64_encode(private_key))
            node = VirtualNode(config_path)
            NodeDB(node.node_num, node.meshdb_path).upsert(
                node_num=int("12345678", 16),
                public_key=b64_encode(peer_public_key),
            )

            sent: list[bytes] = []
            original_sendto = conn.sendto
            original_host = conn.host
            original_port = conn.port
            try:
                node.connect_send_socket = lambda: None
                conn.host = "224.0.0.69"
                conn.port = 4403
                conn.sendto = lambda data, addr: sent.append(data)
                packet_id = node.send_text("!12345678", "store outbound pki", pki_mode="on")
            finally:
                conn.sendto = original_sendto
                conn.host = original_host
                conn.port = original_port

            self.assertEqual(len(sent), 1)
            packet = mesh_pb2.MeshPacket()
            packet.ParseFromString(sent[0])
            self.assertEqual(packet.id, packet_id)
            self.assertTrue(packet.pki_encrypted)
            self.assertEqual(packet.channel, 0)

            with sqlite3.connect(Path(node.meshdb_path) / f"{node.node_num}.db") as con:
                row = con.execute(
                    f'SELECT node_num, message_text, packet_id, to_node, channel, want_ack, pki_encrypted '
                    f'FROM "{node.node_num}_0_messages" WHERE packet_id = ?',
                    (packet_id,),
                ).fetchone()

            self.assertEqual(
                row,
                (
                    str(node.node_num),
                    "store outbound pki",
                    packet_id,
                    int("12345678", 16),
                    0,
                    1,
                    1,
                ),
            )

    def test_incoming_want_ack_text_message_triggers_routing_ack(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _public_key, private_key = generate_keypair()
            config_path = self._write_temp_config(root, b64_encode(private_key))
            node = VirtualNode(config_path)

            sent: list[bytes] = []
            original_sendto = conn.sendto
            original_host = conn.host
            original_port = conn.port
            try:
                conn.host = "224.0.0.69"
                conn.port = 4403
                conn.sendto = lambda data, addr: sent.append(data)

                inbound = mesh_pb2.MeshPacket()
                inbound.id = 4242
                setattr(inbound, "from", int("12345678", 16))
                inbound.to = node.node_num
                inbound.want_ack = True
                inbound.channel = 0
                inbound.hop_limit = 3
                inbound.hop_start = 3
                inbound.decoded.portnum = portnums_pb2.PortNum.TEXT_MESSAGE_APP
                inbound.decoded.payload = b"ping"

                node._maybe_send_ack(inbound)
            finally:
                conn.sendto = original_sendto
                conn.host = original_host
                conn.port = original_port

            self.assertEqual(len(sent), 1)
            ack_packet = mesh_pb2.MeshPacket()
            ack_packet.ParseFromString(sent[0])
            self.assertEqual(ack_packet.to, int("12345678", 16))
            self.assertTrue(ack_packet.want_ack)
            decoded = decrypt_channel_packet(ack_packet, node.config.channel.psk)
            self.assertIsNotNone(decoded)
            self.assertEqual(decoded.portnum, portnums_pb2.PortNum.ROUTING_APP)
            self.assertEqual(decoded.request_id, 4242)
            routing = mesh_pb2.Routing()
            routing.ParseFromString(decoded.payload)
            self.assertEqual(routing.error_reason, mesh_pb2.Routing.Error.NONE)

    def test_incoming_want_response_nodeinfo_request_triggers_nodeinfo_reply(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _public_key, private_key = generate_keypair()
            config_path = self._write_temp_config(root, b64_encode(private_key))
            node = VirtualNode(config_path)

            sent: list[bytes] = []
            original_sendto = conn.sendto
            original_host = conn.host
            original_port = conn.port
            try:
                node.connect_send_socket = lambda: None
                conn.host = "224.0.0.69"
                conn.port = 4403
                conn.sendto = lambda data, addr: sent.append(data)

                inbound = mesh_pb2.MeshPacket()
                inbound.id = 4243
                setattr(inbound, "from", int("12345678", 16))
                inbound.to = node.node_num
                inbound.channel = 0
                inbound.hop_limit = 3
                inbound.hop_start = 3
                inbound.decoded.portnum = portnums_pb2.PortNum.NODEINFO_APP
                inbound.decoded.want_response = True

                node._maybe_send_response(inbound)
            finally:
                conn.sendto = original_sendto
                conn.host = original_host
                conn.port = original_port

            self.assertEqual(len(sent), 1)
            reply_packet = mesh_pb2.MeshPacket()
            reply_packet.ParseFromString(sent[0])
            self.assertEqual(reply_packet.to, int("12345678", 16))
            decoded = decrypt_channel_packet(reply_packet, node.config.channel.psk)
            self.assertIsNotNone(decoded)
            self.assertEqual(decoded.portnum, portnums_pb2.PortNum.NODEINFO_APP)
            self.assertEqual(decoded.request_id, 4243)
            user = mesh_pb2.User()
            user.ParseFromString(decoded.payload)
            self.assertEqual(user.id, node.config.node_id)

    def test_incoming_want_response_position_request_triggers_position_reply(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _public_key, private_key = generate_keypair()
            config_path = self._write_temp_config(root, b64_encode(private_key))
            payload = json.loads(config_path.read_text(encoding="utf-8"))
            payload["position"] = {
                "enabled": True,
                "latitude": 45.523064,
                "longitude": -122.676483,
                "altitude": 27,
                "position_interval_seconds": 900,
            }
            config_path.write_text(json.dumps(payload), encoding="utf-8")
            node = VirtualNode(config_path)

            sent: list[bytes] = []
            original_sendto = conn.sendto
            original_host = conn.host
            original_port = conn.port
            try:
                node.connect_send_socket = lambda: None
                conn.host = "224.0.0.69"
                conn.port = 4403
                conn.sendto = lambda data, addr: sent.append(data)

                inbound = mesh_pb2.MeshPacket()
                inbound.id = 4244
                setattr(inbound, "from", int("12345678", 16))
                inbound.to = node.node_num
                inbound.channel = 0
                inbound.hop_limit = 3
                inbound.hop_start = 3
                inbound.decoded.portnum = portnums_pb2.PortNum.POSITION_APP
                inbound.decoded.want_response = True

                node._maybe_send_response(inbound)
            finally:
                conn.sendto = original_sendto
                conn.host = original_host
                conn.port = original_port

            self.assertEqual(len(sent), 1)
            reply_packet = mesh_pb2.MeshPacket()
            reply_packet.ParseFromString(sent[0])
            self.assertEqual(reply_packet.to, int("12345678", 16))
            decoded = decrypt_channel_packet(reply_packet, node.config.channel.psk)
            self.assertIsNotNone(decoded)
            self.assertEqual(decoded.portnum, portnums_pb2.PortNum.POSITION_APP)
            self.assertEqual(decoded.request_id, 4244)
            position = mesh_pb2.Position()
            position.ParseFromString(decoded.payload)
            self.assertEqual(position.latitude_i, int(45.523064 * 1e7))
            self.assertEqual(position.longitude_i, int(-122.676483 * 1e7))
            self.assertEqual(position.altitude, 27)

    def test_incoming_want_response_position_request_without_position_sends_no_response(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _public_key, private_key = generate_keypair()
            config_path = self._write_temp_config(root, b64_encode(private_key))
            node = VirtualNode(config_path)

            sent: list[bytes] = []
            original_sendto = conn.sendto
            original_host = conn.host
            original_port = conn.port
            try:
                conn.host = "224.0.0.69"
                conn.port = 4403
                conn.sendto = lambda data, addr: sent.append(data)

                inbound = mesh_pb2.MeshPacket()
                inbound.id = 4245
                setattr(inbound, "from", int("12345678", 16))
                inbound.to = node.node_num
                inbound.want_ack = True
                inbound.channel = 0
                inbound.hop_limit = 3
                inbound.hop_start = 3
                inbound.decoded.portnum = portnums_pb2.PortNum.POSITION_APP
                inbound.decoded.want_response = True

                node._maybe_send_response(inbound)
            finally:
                conn.sendto = original_sendto
                conn.host = original_host
                conn.port = original_port

            self.assertEqual(len(sent), 1)
            nack_packet = mesh_pb2.MeshPacket()
            nack_packet.ParseFromString(sent[0])
            decoded = decrypt_channel_packet(nack_packet, node.config.channel.psk)
            self.assertIsNotNone(decoded)
            self.assertEqual(decoded.portnum, portnums_pb2.PortNum.ROUTING_APP)
            self.assertEqual(decoded.request_id, 4245)
            routing = mesh_pb2.Routing()
            routing.ParseFromString(decoded.payload)
            self.assertEqual(routing.error_reason, mesh_pb2.Routing.Error.NO_RESPONSE)

    def test_repeated_nodeinfo_want_response_from_same_sender_is_suppressed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _public_key, private_key = generate_keypair()
            config_path = self._write_temp_config(root, b64_encode(private_key))
            node = VirtualNode(config_path)

            sent: list[bytes] = []
            original_sendto = conn.sendto
            original_host = conn.host
            original_port = conn.port
            try:
                node.connect_send_socket = lambda: None
                conn.host = "224.0.0.69"
                conn.port = 4403
                conn.sendto = lambda data, addr: sent.append(data)

                inbound = mesh_pb2.MeshPacket()
                inbound.id = 4246
                setattr(inbound, "from", int("12345678", 16))
                inbound.to = node.node_num
                inbound.rx_time = 1_700_000_000
                inbound.decoded.portnum = portnums_pb2.PortNum.NODEINFO_APP
                inbound.decoded.want_response = True

                node._maybe_send_response(inbound)
                node._last_nodeinfo_sent_monotonic = 0.0

                inbound_repeat = mesh_pb2.MeshPacket()
                inbound_repeat.CopyFrom(inbound)
                inbound_repeat.id = 4247
                inbound_repeat.rx_time = inbound.rx_time + 60

                node._maybe_send_response(inbound_repeat)
            finally:
                conn.sendto = original_sendto
                conn.host = original_host
                conn.port = original_port

            self.assertEqual(len(sent), 1)

    def test_recent_nodeinfo_send_suppresses_nodeinfo_response_without_nak(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _public_key, private_key = generate_keypair()
            config_path = self._write_temp_config(root, b64_encode(private_key))
            node = VirtualNode(config_path)

            sent: list[bytes] = []
            original_sendto = conn.sendto
            original_host = conn.host
            original_port = conn.port
            try:
                conn.host = "224.0.0.69"
                conn.port = 4403
                conn.sendto = lambda data, addr: sent.append(data)
                node._last_nodeinfo_sent_monotonic = time.monotonic()

                inbound = mesh_pb2.MeshPacket()
                inbound.id = 4248
                setattr(inbound, "from", int("12345678", 16))
                inbound.to = node.node_num
                inbound.rx_time = int(time.time())
                inbound.decoded.portnum = portnums_pb2.PortNum.NODEINFO_APP
                inbound.decoded.want_response = True

                node._maybe_send_response(inbound)
            finally:
                conn.sendto = original_sendto
                conn.host = original_host
                conn.port = original_port

            self.assertEqual(sent, [])

    def test_recent_position_reply_suppresses_position_response_without_nak(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _public_key, private_key = generate_keypair()
            config_path = self._write_temp_config(root, b64_encode(private_key))
            payload = json.loads(config_path.read_text(encoding="utf-8"))
            payload["position"] = {
                "enabled": True,
                "latitude": 45.523064,
                "longitude": -122.676483,
                "altitude": 27,
                "position_interval_seconds": 900,
            }
            config_path.write_text(json.dumps(payload), encoding="utf-8")
            node = VirtualNode(config_path)

            sent: list[bytes] = []
            original_sendto = conn.sendto
            original_host = conn.host
            original_port = conn.port
            try:
                conn.host = "224.0.0.69"
                conn.port = 4403
                conn.sendto = lambda data, addr: sent.append(data)
                node._last_position_reply_monotonic = time.monotonic()

                inbound = mesh_pb2.MeshPacket()
                inbound.id = 4249
                setattr(inbound, "from", int("12345678", 16))
                inbound.to = node.node_num
                inbound.decoded.portnum = portnums_pb2.PortNum.POSITION_APP
                inbound.decoded.want_response = True

                node._maybe_send_response(inbound)
            finally:
                conn.sendto = original_sendto
                conn.host = original_host
                conn.port = original_port

            self.assertEqual(sent, [])

    def test_mudp_send_text_message_registers_pending_ack(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _public_key, private_key = generate_keypair()
            config_path = self._write_temp_config(root, b64_encode(private_key))
            VirtualNode(config_path)

            sent: list[bytes] = []
            original_sendto = conn.sendto
            original_host = conn.host
            original_port = conn.port
            try:
                conn.host = "224.0.0.69"
                conn.port = 4403
                conn.sendto = lambda data, addr: sent.append(data)
                mudp_send_text_message(
                    message="hello from mudp",
                    to=int("12345678", 16),
                    want_ack=True,
                )
            finally:
                conn.sendto = original_sendto
                conn.host = original_host
                conn.port = original_port

            self.assertEqual(len(sent), 1)
            packet = mesh_pb2.MeshPacket()
            packet.ParseFromString(sent[0])
            pending = pending_acks.get(packet.id)
            self.assertIsNotNone(pending)
            self.assertEqual(pending.destination, int("12345678", 16))

    def test_resolved_pending_ack_stops_retries(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _public_key, private_key = generate_keypair()
            config_path = self._write_temp_config(root, b64_encode(private_key))
            node = VirtualNode(config_path)

            sent: list[bytes] = []
            original_sendto = conn.sendto
            original_host = conn.host
            original_port = conn.port
            try:
                node.connect_send_socket = lambda: None
                conn.host = "224.0.0.69"
                conn.port = 4403
                conn.sendto = lambda data, addr: sent.append(data)
                packet_id = node.send_text("!12345678", "hello")
                pending = pending_acks.resolve(packet_id)
                self.assertIsNotNone(pending)
                pending_acks.process_due(now=pending.next_retry_monotonic + 1.0)
            finally:
                conn.sendto = original_sendto
                conn.host = original_host
                conn.port = original_port

            self.assertEqual(len(sent), 1)
            self.assertIsNone(pending_acks.get(packet_id))

    def test_outbound_direct_text_retries_until_max_retransmit(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _public_key, private_key = generate_keypair()
            config_path = self._write_temp_config(root, b64_encode(private_key))
            node = VirtualNode(config_path)

            sent: list[bytes] = []
            failures: list[tuple[int, int]] = []

            def on_max_retransmit(pending, error_reason) -> None:
                failures.append((pending.packet_id, error_reason))

            original_sendto = conn.sendto
            original_host = conn.host
            original_port = conn.port
            try:
                pub.subscribe(on_max_retransmit, "mesh.tx.max_retransmit")
                node.connect_send_socket = lambda: None
                conn.host = "224.0.0.69"
                conn.port = 4403
                conn.sendto = lambda data, addr: sent.append(data)
                packet_id = node.send_text("!12345678", "retry me")

                for _ in range(NUM_RELIABLE_RETX - 1):
                    pending = pending_acks.get(packet_id)
                    self.assertIsNotNone(pending)
                    pending_acks.process_due(now=pending.next_retry_monotonic + 0.001)

                final_pending = pending_acks.get(packet_id)
                self.assertIsNotNone(final_pending)
                pending_acks.process_due(now=final_pending.next_retry_monotonic + 0.001)
            finally:
                try:
                    pub.unsubscribe(on_max_retransmit, "mesh.tx.max_retransmit")
                except KeyError:
                    pass
                conn.sendto = original_sendto
                conn.host = original_host
                conn.port = original_port

            self.assertEqual(len(sent), NUM_RELIABLE_RETX)
            self.assertIsNone(pending_acks.get(packet_id))
            self.assertEqual(
                failures,
                [(packet_id, mesh_pb2.Routing.Error.MAX_RETRANSMIT)],
            )

    def test_receive_callback_matches_meshtastic_style(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _public_key, private_key = generate_keypair()
            config_path = self._write_temp_config(root, b64_encode(private_key))
            node = VirtualNode(config_path)

            received: list[tuple[dict[str, object], object]] = []

            def on_receive(packet, interface) -> None:
                received.append((packet, interface))

            node.receive(on_receive)
            try:
                inbound = mesh_pb2.MeshPacket()
                inbound.id = 5151
                setattr(inbound, "from", int("12345678", 16))
                inbound.to = node.node_num
                inbound.channel = 0
                inbound.hop_limit = 3
                inbound.hop_start = 3
                inbound.decoded.portnum = portnums_pb2.PortNum.TEXT_MESSAGE_APP
                inbound.decoded.payload = b"hello"

                node._handle_unique_packet(inbound)
            finally:
                node.unreceive(on_receive)

            self.assertEqual(len(received), 1)
            packet, interface = received[0]
            self.assertIs(interface, node)
            self.assertEqual(packet["from"], int("12345678", 16))
            self.assertEqual(packet["to"], node.node_num)
            self.assertEqual(packet["decoded"]["portnum"], "TEXT_MESSAGE_APP")
            self.assertEqual(packet["decoded"]["payload"], b"hello")
            self.assertEqual(packet["decoded"]["text"], "hello")
            self.assertIs(packet["raw"], inbound)

    def test_sendText_compat_returns_meshpacket(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _public_key, private_key = generate_keypair()
            config_path = self._write_temp_config(root, b64_encode(private_key))
            node = VirtualNode(config_path)

            sent: list[bytes] = []
            original_sendto = conn.sendto
            original_host = conn.host
            original_port = conn.port
            try:
                node.connect_send_socket = lambda: None
                conn.host = "224.0.0.69"
                conn.port = 4403
                conn.sendto = lambda data, addr: sent.append(data)

                packet = node.sendText(
                    "compat hello",
                    destinationId="!12345678",
                    wantAck=True,
                    replyId=5150,
                    hopLimit=5,
                )
            finally:
                conn.sendto = original_sendto
                conn.host = original_host
                conn.port = original_port

            self.assertEqual(len(sent), 1)
            self.assertIsInstance(packet, mesh_pb2.MeshPacket)
            self.assertEqual(packet.to, int("12345678", 16))
            self.assertTrue(packet.want_ack)
            self.assertEqual(packet.hop_limit, 5)
            decoded = decrypt_channel_packet(packet, node.config.channel.psk)
            self.assertIsNotNone(decoded)
            self.assertEqual(decoded.portnum, portnums_pb2.PortNum.TEXT_MESSAGE_APP)
            self.assertEqual(decoded.reply_id, 5150)
            self.assertEqual(decoded.payload, b"compat hello")

    def test_sendData_onResponse_callback_receives_matching_response(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _public_key, private_key = generate_keypair()
            config_path = self._write_temp_config(root, b64_encode(private_key))
            node = VirtualNode(config_path)

            callbacks: list[dict[str, object]] = []
            original_sendto = conn.sendto
            original_host = conn.host
            original_port = conn.port
            try:
                node.connect_send_socket = lambda: None
                conn.host = "224.0.0.69"
                conn.port = 4403
                conn.sendto = lambda data, addr: None

                outbound = node.sendData(
                    b"request",
                    destinationId="!12345678",
                    portNum=portnums_pb2.PortNum.PRIVATE_APP,
                    wantResponse=True,
                    onResponse=lambda packet: callbacks.append(packet),
                )

                inbound = mesh_pb2.MeshPacket()
                inbound.id = 6001
                setattr(inbound, "from", int("12345678", 16))
                inbound.to = node.node_num
                inbound.decoded.portnum = portnums_pb2.PortNum.POSITION_APP
                inbound.decoded.request_id = outbound.id
                inbound.decoded.payload = mesh_pb2.Position(
                    latitude_i=int(45.523064 * 1e7),
                    longitude_i=int(-122.676483 * 1e7),
                ).SerializeToString()

                node._handle_compat_response_packet(
                    node._mesh_interface_packet_dict(inbound),
                    node,
                )
            finally:
                conn.sendto = original_sendto
                conn.host = original_host
                conn.port = original_port

            self.assertEqual(len(callbacks), 1)
            self.assertEqual(callbacks[0]["decoded"]["portnum"], "POSITION_APP")
            self.assertEqual(callbacks[0]["decoded"]["requestId"], outbound.id)

    def test_autoresponder_ignores_broadcast_text(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _public_key, private_key = generate_keypair()
            config_path = self._write_temp_config(root, b64_encode(private_key))
            node = VirtualNode(config_path)
            responder = DirectMessageAutoResponder(node)

            replies: list[tuple[int, str, int, bool]] = []
            original_send_reply = node.send_reply
            try:
                node.send_reply = lambda destination, message, **kwargs: replies.append(
                    (int(destination), str(message), int(kwargs["reply_id"]), bool(kwargs.get("emoji", False)))
                )

                inbound = mesh_pb2.MeshPacket()
                inbound.id = 5150
                setattr(inbound, "from", int("12345678", 16))
                inbound.to = BROADCAST_NUM
                inbound.decoded.portnum = portnums_pb2.PortNum.TEXT_MESSAGE_APP
                inbound.decoded.payload = b"hello everyone"

                responder.on_receive(
                    {
                        "from": int("12345678", 16),
                        "to": BROADCAST_NUM,
                        "decoded": {"text": "hello everyone"},
                        "raw": inbound,
                    },
                    node,
                )
            finally:
                node.send_reply = original_send_reply

            self.assertEqual(replies, [])

    def test_reply_to_packet_reuses_reply_envelope(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _public_key, private_key = generate_keypair()
            config_path = self._write_temp_config(root, b64_encode(private_key))
            node = VirtualNode(config_path)

            calls: list[dict[str, object]] = []
            original_send_reply = node.send_reply
            try:
                node.send_reply = lambda destination, message, **kwargs: calls.append(
                    {
                        "destination": int(destination),
                        "message": str(message),
                        "reply_id": int(kwargs["reply_id"]),
                        "hop_limit": int(kwargs["hop_limit"]),
                        "hop_start": int(kwargs["hop_start"]),
                        "emoji": bool(kwargs.get("emoji", False)),
                        "pki_mode": str(kwargs.get("pki_mode")),
                    }
                )

                inbound = mesh_pb2.MeshPacket()
                inbound.id = 9001
                setattr(inbound, "from", int("12345678", 16))
                inbound.to = node.node_num
                inbound.hop_limit = 2
                inbound.hop_start = 4

                node.reply_to_packet(inbound, "pong", emoji=True)
            finally:
                node.send_reply = original_send_reply

            self.assertEqual(
                calls,
                [
                    {
                        "destination": int("12345678", 16),
                        "message": "pong",
                        "reply_id": 9001,
                        "hop_limit": 2,
                        "hop_start": 4,
                        "emoji": True,
                        "pki_mode": "auto",
                    }
                ],
            )

    def test_mudp_packet_stream_detects_duplicates(self) -> None:
        stream = UDPPacketStream("224.0.0.69", 4403, key="AQ==", parse_payload=False)

        inbound = mesh_pb2.MeshPacket()
        inbound.id = 7001
        setattr(inbound, "from", int("12345678", 16))
        inbound.to = int("89abcdef", 16)
        inbound.decoded.portnum = portnums_pb2.PortNum.TEXT_MESSAGE_APP
        inbound.decoded.payload = b"hello"

        self.assertFalse(stream._is_duplicate_packet(inbound))
        self.assertTrue(stream._is_duplicate_packet(inbound))

    def test_build_mesh_packet_supports_meshpacket_envelope_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _public_key, private_key = generate_keypair()
            config_path = self._write_temp_config(root, b64_encode(private_key))
            VirtualNode(config_path)

            data = mesh_pb2.Data()
            data.portnum = portnums_pb2.PortNum.TEXT_MESSAGE_APP
            data.payload = b"hello"

            packet = build_mesh_packet(
                data,
                to=int("12345678", 16),
                want_ack=True,
                priority="HIGH",
                delayed="DELAYED_DIRECT",
                via_mqtt=True,
                next_hop=0x44,
                relay_node=0x55,
                tx_after=123456,
                public_key=b"\x01\x02\x03",
                pki_encrypted=True,
                transport_mechanism="TRANSPORT_API",
                rx_time=111,
                rx_snr=4.5,
                rx_rssi=-70,
            )

            self.assertTrue(packet.want_ack)
            self.assertEqual(packet.priority, mesh_pb2.MeshPacket.Priority.HIGH)
            self.assertEqual(packet.delayed, mesh_pb2.MeshPacket.Delayed.DELAYED_DIRECT)
            self.assertTrue(packet.via_mqtt)
            self.assertEqual(packet.next_hop, 0x44)
            self.assertEqual(packet.relay_node, 0x55)
            self.assertEqual(packet.tx_after, 123456)
            self.assertEqual(bytes(packet.public_key), b"\x01\x02\x03")
            self.assertTrue(packet.pki_encrypted)
            self.assertEqual(
                packet.transport_mechanism,
                mesh_pb2.MeshPacket.TransportMechanism.TRANSPORT_API,
            )
            self.assertEqual(packet.rx_time, 111)
            self.assertEqual(packet.rx_snr, 4.5)
            self.assertEqual(packet.rx_rssi, -70)

    def test_normalize_packet_preserves_meshpacket_envelope_fields(self) -> None:
        packet = mesh_pb2.MeshPacket()
        packet.id = 8080
        setattr(packet, "from", int("89abcdef", 16))
        packet.to = int("12345678", 16)
        packet.channel = 7
        packet.rx_time = 222
        packet.rx_snr = 3.25
        packet.hop_limit = 3
        packet.want_ack = True
        packet.priority = mesh_pb2.MeshPacket.Priority.ACK
        packet.rx_rssi = -90
        packet.via_mqtt = True
        packet.hop_start = 5
        packet.public_key = b"\x0a\x0b\x0c"
        packet.pki_encrypted = True
        packet.next_hop = 0x11
        packet.relay_node = 0x22
        packet.tx_after = 333
        packet.transport_mechanism = mesh_pb2.MeshPacket.TransportMechanism.TRANSPORT_MULTICAST_UDP
        packet.decoded.portnum = portnums_pb2.PortNum.TEXT_MESSAGE_APP
        packet.decoded.payload = b"hello"

        normalized = normalize_packet(packet, "udp")

        self.assertEqual(normalized["from"], int("89abcdef", 16))
        self.assertEqual(normalized["to"], int("12345678", 16))
        self.assertEqual(normalized["id"], 8080)
        self.assertEqual(normalized["channel"], 7)
        self.assertEqual(normalized["rxTime"], 222)
        self.assertEqual(normalized["snr"], 3.25)
        self.assertEqual(normalized["hopLimit"], 3)
        self.assertTrue(normalized["wantAck"])
        self.assertEqual(normalized["priority"], "ACK")
        self.assertEqual(normalized["rxRssi"], -90)
        self.assertTrue(normalized["viaMqtt"])
        self.assertEqual(normalized["hopStart"], 5)
        self.assertEqual(normalized["publicKey"], "CgsM")
        self.assertTrue(normalized["pkiEncrypted"])
        self.assertEqual(normalized["nextHop"], 0x11)
        self.assertEqual(normalized["relayNode"], 0x22)
        self.assertEqual(normalized["txAfter"], 333)
        self.assertEqual(normalized["transportMechanism"], "TRANSPORT_MULTICAST_UDP")
        self.assertEqual(normalized["decoded"]["text"], "hello")

    def test_handle_packet_persists_message_packet_meta_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            db_root = root / "meshdb"
            db_root.mkdir()
            owner = int("89abcdef", 16)

            packet = mesh_pb2.MeshPacket()
            packet.id = 9002
            setattr(packet, "from", int("12345678", 16))
            packet.to = owner
            packet.channel = 7
            packet.rx_time = 444
            packet.rx_snr = 4.25
            packet.rx_rssi = -72
            packet.hop_limit = 3
            packet.want_ack = True
            packet.priority = mesh_pb2.MeshPacket.Priority.HIGH
            packet.delayed = mesh_pb2.MeshPacket.Delayed.DELAYED_DIRECT
            packet.via_mqtt = True
            packet.hop_start = 5
            packet.public_key = b"\x01\x02\x03"
            packet.pki_encrypted = True
            packet.next_hop = 0x11
            packet.relay_node = 0x22
            packet.tx_after = 555
            packet.transport_mechanism = mesh_pb2.MeshPacket.TransportMechanism.TRANSPORT_MULTICAST_UDP
            packet.decoded.portnum = portnums_pb2.PortNum.TEXT_MESSAGE_APP
            packet.decoded.payload = b"saved to db"

            stored = handle_packet(normalize_packet(packet, "udp"), node_database_number=owner, db_path=str(db_root))
            self.assertTrue(stored["message"])

            with sqlite3.connect(db_root / f"{owner}.db") as con:
                row = con.execute(
                    f'SELECT message_text, timestamp, to_node, packet_id, channel, rx_snr, rx_rssi, hop_limit, '
                    f'want_ack, priority, delayed, via_mqtt, hop_start, public_key, pki_encrypted, '
                    f'next_hop, relay_node, tx_after, transport_mechanism '
                    f'FROM "{owner}_7_messages" WHERE node_num = ?',
                    (str(int("12345678", 16)),),
                ).fetchone()

            self.assertEqual(
                row,
                (
                    "saved to db",
                    444,
                    owner,
                    9002,
                    7,
                    4.25,
                    -72,
                    3,
                    1,
                    "HIGH",
                    "DELAYED_DIRECT",
                    1,
                    5,
                    "AQID",
                    1,
                    0x11,
                    0x22,
                    555,
                    "TRANSPORT_MULTICAST_UDP",
                ),
            )

    def test_handle_packet_persists_location_packet_meta_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            db_root = root / "meshdb"
            db_root.mkdir()
            owner = int("89abcdef", 16)

            position = mesh_pb2.Position()
            position.latitude_i = int(45.523064 * 1e7)
            position.longitude_i = int(-122.676483 * 1e7)
            position.altitude = 27

            packet = mesh_pb2.MeshPacket()
            packet.id = 9003
            setattr(packet, "from", int("12345678", 16))
            packet.to = BROADCAST_NUM
            packet.channel = 1
            packet.rx_time = 555
            packet.rx_snr = 2.5
            packet.rx_rssi = -85
            packet.hop_limit = 2
            packet.want_ack = False
            packet.priority = mesh_pb2.MeshPacket.Priority.BACKGROUND
            packet.via_mqtt = False
            packet.hop_start = 2
            packet.next_hop = 0x44
            packet.relay_node = 0x55
            packet.tx_after = 777
            packet.transport_mechanism = mesh_pb2.MeshPacket.TransportMechanism.TRANSPORT_MULTICAST_UDP
            packet.decoded.portnum = portnums_pb2.PortNum.POSITION_APP
            packet.decoded.payload = position.SerializeToString()

            stored = handle_packet(normalize_packet(packet, "udp"), node_database_number=owner, db_path=str(db_root))
            self.assertTrue(stored["position"])

            with sqlite3.connect(db_root / f"{owner}.db") as con:
                row = con.execute(
                    f'SELECT latitude_i, longitude_i, altitude, timestamp, packet_id, rx_snr, rx_rssi, '
                    f'priority, hop_start, next_hop, relay_node, tx_after, transport_mechanism '
                    f'FROM "{owner}_location" WHERE node_num = ?',
                    (str(int("12345678", 16)),),
                ).fetchone()

            self.assertEqual(
                row,
                (
                    int(45.523064 * 1e7),
                    int(-122.676483 * 1e7),
                    27.0,
                    555,
                    9003,
                    2.5,
                    -85,
                    "BACKGROUND",
                    2,
                    0x44,
                    0x55,
                    777,
                    "TRANSPORT_MULTICAST_UDP",
                ),
            )

    def test_handle_packet_persists_telemetry_packet_meta_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            db_root = root / "meshdb"
            db_root.mkdir()
            owner = int("89abcdef", 16)

            packet = {
                "from": int("12345678", 16),
                "to": owner,
                "id": 9004,
                "channel": 3,
                "rxTime": 666,
                "snr": 1.75,
                "rxRssi": -67,
                "hopLimit": 4,
                "wantAck": True,
                "priority": "HIGH",
                "delayed": "DELAYED_DIRECT",
                "viaMqtt": True,
                "hopStart": 4,
                "publicKey": "AQID",
                "pkiEncrypted": True,
                "nextHop": 0x66,
                "relayNode": 0x77,
                "txAfter": 888,
                "transportMechanism": "TRANSPORT_MULTICAST_UDP",
                "decoded": {
                    "portnum": "TELEMETRY_APP",
                    "telemetry": {
                        "deviceMetrics": {
                            "batteryLevel": 91,
                            "voltage": 4.11,
                            "channelUtilization": 12.5,
                            "airUtilTx": 2.25,
                            "uptimeSeconds": 12345,
                        }
                    },
                },
            }

            stored = handle_packet(packet, node_database_number=owner, db_path=str(db_root))
            self.assertTrue(stored["telemetry"])

            with sqlite3.connect(db_root / f"{owner}.db") as con:
                row = con.execute(
                    f'SELECT battery_level, voltage, channel_utilization, air_util_tx, uptime_seconds, timestamp, '
                    f'packet_id, rx_snr, rx_rssi, want_ack, priority, delayed, via_mqtt, public_key, '
                    f'pki_encrypted, next_hop, relay_node, tx_after, transport_mechanism '
                    f'FROM "{owner}_telemetry_device" WHERE node_num = ?',
                    (str(int("12345678", 16)),),
                ).fetchone()

            self.assertEqual(
                row,
                (
                    91.0,
                    4.11,
                    12.5,
                    2.25,
                    12345,
                    666,
                    9004,
                    1.75,
                    -67,
                    1,
                    "HIGH",
                    "DELAYED_DIRECT",
                    1,
                    "AQID",
                    1,
                    0x66,
                    0x77,
                    888,
                    "TRANSPORT_MULTICAST_UDP",
                ),
            )


if __name__ == "__main__":
    unittest.main()
