# Examples

Run these from the repository root.
Most examples accept `--vnode-file path/to/node.json`; `--config` still works as an alias.

## DM autoresponder

Listens for direct text messages addressed to this node and replies with a DM.
It skips duplicates, ignores replies, and alternates between an emoji and plain-text response.

```bash
.venv/bin/python examples/autoresponder.py --vnode-file node.json
```

## Print packets

Prints every packet seen by the node using the mirrored `meshtastic.receive` callback shape.
Useful for watching multicast traffic while writing code that looks like the Meshtastic Python library.

```bash
.venv/bin/python examples/listen_packets.py --vnode-file node.json
```

## Send a DM

Sends a single direct message using the virtual node runtime.
PKI is used automatically when the destination has a stored public key.

```bash
.venv/bin/python examples/send_dm.py --vnode-file node.json --to '!1234abcd' --message 'hello'
```

## Embed as a library

Shows the minimal pattern an application would use to embed `vnode` directly:
construct `VirtualNode`, use `receive()`, start it, call both the snake_case vnode API and the mirrored Meshtastic-style API, and stop cleanly.
This example does not use CLI arguments; edit the constants at the top of the file instead.

```bash
.venv/bin/python examples/library_embed.py
```

## Meshtastic-compatible API

Shows the mirrored Meshtastic Python API surface on `VirtualNode`:
subscribe to `meshtastic.*` pubsub topics, inspect `getMyNodeInfo()`, and call `sendText()`.
This example does not use CLI arguments; edit the constants at the top of the file instead.

```bash
.venv/bin/python examples/meshtastic_compat.py
```

## Try serial, then fall back to vnode

Attempts a short Meshtastic serial connection first and prints packets from the real node if one is attached.
If no serial device is available, it starts `vnode` instead and prints packets from the virtual node using the same `on_receive(packet, interface)` callback.
This example does not use CLI arguments; edit the constants at the top of the file instead.

```bash
.venv/bin/python examples/serial_or_vnode.py
```

## Watch ACK and retry events

Subscribes to `mudp` reliability events and prints ACK, NAK, retry, and max-retransmit updates.
Optionally sends a startup DM so you can watch the full reliability lifecycle immediately.

```bash
.venv/bin/python examples/watch_reliability.py --vnode-file node.json --to '!1234abcd' --message 'hello'
```
