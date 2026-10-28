"""Identity migration and firmware-compatible on-wire signing tests."""

import json
from pathlib import Path
import tempfile
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from google.protobuf import descriptor_pb2, descriptor_pool, message_factory
from meshtastic import mesh_pb2, portnums_pb2
from mudp.encryption import decrypt_packet
from mudp.singleton import conn
from vnode.config import NodeConfig
from vnode.crypto import (
    b64_encode,
    derive_public_key,
    node_id_from_public_key,
    sign_data,
    signing_buffer,
)
from vnode.runtime import VirtualNode


def signature_data(data):
    """Decode field 10 independently when testing with pre-2.8 protobufs."""
    if "xeddsa_signature" in data.DESCRIPTOR.fields_by_name:
        return data
    schema = descriptor_pb2.FileDescriptorProto(
        name="vnode_test_signed_data.proto",
        package="vnode.tests",
        syntax="proto3",
        dependency=[mesh_pb2.DESCRIPTOR.name],
    )
    message = schema.message_type.add()
    mesh_pb2.Data.DESCRIPTOR.CopyToProto(message)
    message.name = "SignedData"
    message.field.add(
        name="xeddsa_signature",
        number=10,
        type=descriptor_pb2.FieldDescriptorProto.TYPE_BYTES,
        label=descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL,
    )
    pool = descriptor_pool.Default()
    pool.Add(schema)
    cls = message_factory.GetMessageClass(
        pool.FindMessageTypeByName("vnode.tests.SignedData")
    )
    return cls.FromString(data.SerializeToString())


class SigningTest(unittest.TestCase):
    PRIVATE = bytes.fromhex(
        "a00330633e63522f8a4d81ec6d9d1e6617f6c8ffd3a4c698229537d44e522277"
    )

    def verifier(self):
        # Independent implementation of CryptoEngine::curve_to_ed_pub, then
        # OpenSSL Ed25519 verification (not the signing library's verifier).
        u = int.from_bytes(derive_public_key(self.PRIVATE), "little") & ((1 << 255) - 1)
        p = (1 << 255) - 19
        y = (u - 1) * pow(u + 1, p - 2, p) % p
        return Ed25519PublicKey.from_public_bytes(y.to_bytes(32, "little"))

    def test_crc32_identity_and_key_rotation(self):
        self.assertEqual(node_id_from_public_key(bytes(32)), 0x190A55AD)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "node.json"
            path.write_text(
                json.dumps(
                    {
                        "node_id": "!89abcdef",
                        "long_name": "Garry",
                        "short_name": "GAR",
                        "security": {"private_key": b64_encode(self.PRIVATE)},
                    }
                )
            )
            config = NodeConfig.load(path)
            expected = (
                f"!{node_id_from_public_key(derive_public_key(self.PRIVATE)):08x}"
            )
            self.assertEqual(config.node_id, expected)
            self.assertEqual(config.long_name, "Garry")
            self.assertEqual(config.short_name, "GAR")
            self.assertNotIn("node_id", json.loads(path.read_text()))
            self.assertNotIn("node_id", config.to_dict())
            with self.assertRaises(AttributeError):
                config.node_id = "!12345678"
            self.assertEqual(NodeConfig.load(path).to_dict(), config.to_dict())
            payload = json.loads(path.read_text())
            payload["security"]["private_key"] = b64_encode(bytes(range(32)))
            path.write_text(json.dumps(payload))
            self.assertNotEqual(NodeConfig.load(path).node_id, expected)

    def test_exact_firmware_signing_layout(self):
        data = mesh_pb2.Data(
            portnum=1,
            payload=b"test",
            request_id=5,
            reply_id=6,
            emoji=7,
            bitfield=8,
            want_response=True,
        )
        expected = bytes.fromhex(
            "01"
            "01000000"
            "02000000"
            "03000000"
            "01000000"
            "05000000"
            "06000000"
            "07000000"
            "08000000"
            "03"
            "74657374"
        )
        self.assertEqual(signing_buffer(1, 2, 3, data), expected)
        signature = sign_data(self.PRIVATE, 1, 2, 3, data)
        self.verifier().verify(signature, expected)
        for i in range(len(expected)):
            tampered = bytearray(expected)
            tampered[i] ^= 1
            with self.assertRaises(InvalidSignature):
                self.verifier().verify(signature, bytes(tampered))

    def test_absent_bitfield_differs_from_present_zero(self):
        data = mesh_pb2.Data(portnum=1, payload=b"hello")
        absent = signing_buffer(1, 2, 3, data)
        data.bitfield = 0
        self.assertNotEqual(signing_buffer(1, 2, 3, data), absent)

    def test_signed_nodeinfo_on_wire(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "node.json"
            path.write_text(
                json.dumps(
                    {
                        "node_id": "!89abcdef",
                        "long_name": "Garry",
                        "short_name": "GAR",
                        "security": {"private_key": b64_encode(self.PRIVATE)},
                    }
                )
            )
            node = VirtualNode(path)
            with (
                patch.object(node, "connect_send_socket"),
                patch.object(conn, "sendto") as send,
            ):
                node.send_nodeinfo()
            packet = mesh_pb2.MeshPacket.FromString(send.call_args.args[0])
            data = signature_data(decrypt_packet(packet, node.config.channel.psk))
            user = mesh_pb2.User.FromString(data.payload)
            self.assertEqual(
                node_id_from_public_key(user.public_key), getattr(packet, "from")
            )
            self.assertEqual(user.id, node.config.node_id)
            self.assertEqual(user.macaddr, bytes(6))
            self.assertEqual(data.portnum, portnums_pb2.PortNum.NODEINFO_APP)
            self.verifier().verify(
                data.xeddsa_signature,
                signing_buffer(
                    getattr(packet, "from"),
                    packet.id,
                    packet.to,
                    data,
                ),
            )
            # Gateways decode/re-encode User with nanopb, which unconditionally
            # emits fixed-length macaddr. This used to add eight signed bytes.
            original_payload = bytes(data.payload)
            user.macaddr = bytes(6)
            data.payload = user.SerializeToString()
            self.assertEqual(data.payload, original_payload)
            self.verifier().verify(
                data.xeddsa_signature,
                signing_buffer(
                    getattr(packet, "from"),
                    packet.id,
                    packet.to,
                    data,
                ),
            )
            self.assertEqual(len(data.xeddsa_signature), 64)
            self.assertLessEqual(data.ByteSize() + 16, 255)
            # Persistence must succeed as part of the send.
            self.assertTrue((Path(node.meshdb_path) / f"{node.node_num}.db").exists())

    def test_broadcast_signing_gate_and_size_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            node = VirtualNode(Path(directory) / "node.json")
            with (
                patch.object(node, "connect_send_socket"),
                patch.object(conn, "sendto"),
            ):
                for payload_size, should_sign in ((1, True), (168, True), (169, False)):
                    data = mesh_pb2.Data(portnum=1, payload=b"x" * payload_size)
                    packet = node._send_data_packet(
                        data, destination=0xFFFFFFFF, force_pki=False
                    )
                    decoded = signature_data(
                        decrypt_packet(packet, node.config.channel.psk)
                    )
                    self.assertEqual(bool(decoded.xeddsa_signature), should_sign)
                    self.assertFalse(signature_data(data).xeddsa_signature)
                traceroute = mesh_pb2.Data(
                    portnum=portnums_pb2.PortNum.TRACEROUTE_APP, payload=b"route"
                )
                packet = node._send_data_packet(
                    traceroute, destination=0xFFFFFFFF, force_pki=False
                )
                self.assertFalse(
                    signature_data(
                        decrypt_packet(packet, node.config.channel.psk)
                    ).xeddsa_signature
                )
                packet = node.sendData(b"hello", destinationId="!12345678")
                self.assertFalse(
                    signature_data(
                        decrypt_packet(packet, node.config.channel.psk)
                    ).xeddsa_signature
                )


if __name__ == "__main__":
    unittest.main()
