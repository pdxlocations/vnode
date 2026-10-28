"""meshdb 0.2 channel scope and legacy-contact migration."""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from meshdb import NodeDB
from meshtastic import mesh_pb2
from vnode import NodeConfig, VirtualNode, b64_encode, generate_keypair


class ChannelStorageTests(unittest.TestCase):
    def test_legacy_contact_keys_are_copied_without_overwriting_current_records(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = NodeConfig.load(root / "node.json")
            owner = int(config.node_id[1:], 16)
            data = root / "data"
            data.mkdir()
            key, _ = generate_keypair()
            legacy = NodeDB(owner, str(data))
            legacy.upsert(123456, long_name="Peer", public_key=b64_encode(key))
            node = VirtualNode(root / "node.json")
            self.assertEqual(node._resolve_destination("Peer"), 123456)
            self.assertEqual(node._lookup_public_key(123456), key)
            self.assertEqual(node._known_node_count(), 2)
            # Import is idempotent and must not replace newer channel records.
            legacy.upsert(123456, long_name="Old name", public_key="old")
            restarted = VirtualNode(root / "node.json")
            self.assertEqual(restarted._lookup_public_key(123456), key)
            self.assertEqual(restarted._resolve_destination("Peer"), 123456)
            current = NodeDB(owner, str(data), **node._db_scope)
            with current.connect() as con:
                con.execute(f"DELETE FROM {current.table} WHERE node_num=123456")
            again = VirtualNode(root / "node.json")
            self.assertIsNone(again._lookup_public_key(123456))

    def test_received_nodeinfo_is_available_for_destination_and_key_lookup(self):
        with tempfile.TemporaryDirectory() as directory:
            node = VirtualNode(Path(directory) / "node.json")
            key, _ = generate_keypair()
            packet = mesh_pb2.MeshPacket(to=0xFFFFFFFF, channel=0)
            setattr(packet, "from", 123456)
            packet.decoded.portnum = 4
            packet.decoded.payload = mesh_pb2.User(
                long_name="Incoming", public_key=key
            ).SerializeToString()
            node._persist_packet(packet)
            self.assertEqual(node._resolve_destination("Incoming"), 123456)
            self.assertEqual(node._lookup_public_key(123456), key)
