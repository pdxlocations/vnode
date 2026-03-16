# Examples

Run these from the repository root.
Each example accepts `--vnode-file path/to/node.json`; `--config` still works as an alias.

## DM autoresponder

Listens for direct text messages addressed to this node and replies with a DM.
It skips duplicates, ignores replies, and alternates between an emoji and plain-text response.

```bash
.venv/bin/python examples/autoresponder.py --vnode-file node.json
```

## Basic subscriptions

Shows the minimal `node.receive(callback)` / `node.unreceive(callback)` pattern using
Meshtastic-style `(packet, interface)` callbacks. Edit `VNODE_FILE` in the script if you
want to use a config path other than `node.json`.

```bash
.venv/bin/python examples/basic_subscriptions.py
```

## Serial or vnode fallback

Tries to connect to a real serial Meshtastic node first. If no serial device is available,
it falls back to a local `VirtualNode` and keeps the same `meshtastic.receive` callback shape.
Edit `VNODE_FILE` or `SERIAL_DEVICE` in the script if you want to change either value.

```bash
.venv/bin/python examples/serial_or_vnode.py
```

## Print packets

Prints every packet seen by the node, including decoded text when available.
Useful for watching multicast traffic and confirming PKI decode behavior.

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
construct `VirtualNode`, subscribe to packets, start it, call common public APIs, and stop cleanly.
This example does not use CLI arguments; edit the constants at the top of the file instead.

```bash
.venv/bin/python examples/library_embed.py
```

## Watch ACK and retry events

Subscribes to `mudp` reliability events and prints ACK, NAK, retry, and max-retransmit updates.
Optionally sends a startup DM so you can watch the full reliability lifecycle immediately.

```bash
.venv/bin/python examples/watch_reliability.py --vnode-file node.json --to '!1234abcd' --message 'hello'
```
