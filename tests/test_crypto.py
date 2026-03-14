import unittest
import json
import tempfile
import time
from pathlib import Path

from meshtastic import BROADCAST_NUM
from examples.autoresponder import DirectMessageAutoResponder
from pubsub import pub
from meshtastic.protobuf import mesh_pb2, portnums_pb2
from mudp import UDPPacketStream
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
                        "node_id": "!11223344",
                        "long_name": "Template Node",
                        "short_name": "TPL",
                        "hw_model": "ANDROID_SIM",
                        "role": "CLIENT",
                        "is_licensed": False,
                        "hop_limit": 5,
                        "broadcasts": {
                            "send_startup_nodeinfo": False,
                            "nodeinfo_interval_seconds": 120,
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
            self.assertEqual(node.config.node_id, "!11223344")
            self.assertEqual(node.config.long_name, "Template Node")
            self.assertEqual(node.config.channel.name, "TemplateChannel")
            self.assertEqual(node.config.hop_limit, 5)
            self.assertTrue(written["security"]["private_key"])

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

                responder.on_packet(inbound)
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


if __name__ == "__main__":
    unittest.main()
