# Examples

Run these from the repository root.

## DM autoresponder

Listens for direct text messages addressed to this node and replies with a DM.
It skips duplicates, ignores replies, and alternates between an emoji and plain-text response.

```bash
.venv/bin/python examples/autoresponder.py
```

## Print packets

Prints every packet seen by the node, including decoded text when available.
Useful for watching multicast traffic and confirming PKI decode behavior.

```bash
.venv/bin/python examples/listen_packets.py
```

## Send a DM

Sends a single direct message using the virtual node runtime.
PKI is used automatically when the destination has a stored public key.

```bash
.venv/bin/python examples/send_dm.py --to '!1234abcd' --message 'hello'
```

## Watch ACK and retry events

Subscribes to `mudp` reliability events and prints ACK, NAK, retry, and max-retransmit updates.
Optionally sends a startup DM so you can watch the full reliability lifecycle immediately.

```bash
.venv/bin/python examples/watch_reliability.py --to '!1234abcd' --message 'hello'
```
