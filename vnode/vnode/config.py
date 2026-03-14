from __future__ import annotations

import json
import secrets
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Union


@dataclass
class BroadcastConfig:
    send_startup_nodeinfo: bool = True
    nodeinfo_interval_seconds: int = 900


@dataclass
class PositionConfig:
    enabled: bool = False
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    altitude: Optional[int] = None
    position_interval_seconds: int = 900


@dataclass
class ChannelConfig:
    name: str = "LongFast"
    psk: str = "AQ=="


@dataclass
class UdpConfig:
    mcast_group: str = "224.0.0.69"
    mcast_port: int = 4403


@dataclass
class MeshDbConfig:
    path: str = "./data"


@dataclass
class SecurityConfig:
    public_key: str = ""
    private_key: str = ""


@dataclass
class NodeConfig:
    node_id: str = ""
    long_name: str = "Virtual Meshtastic Node"
    short_name: str = "VND"
    hw_model: Union[str, int] = "ANDROID_SIM"
    role: Union[str, int] = "CLIENT"
    is_licensed: bool = False
    hop_limit: int = 3
    broadcasts: BroadcastConfig = field(default_factory=BroadcastConfig)
    position: PositionConfig = field(default_factory=PositionConfig)
    channel: ChannelConfig = field(default_factory=ChannelConfig)
    udp: UdpConfig = field(default_factory=UdpConfig)
    meshdb: MeshDbConfig = field(default_factory=MeshDbConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)

    @classmethod
    def load(cls, path: Union[str, Path]) -> "NodeConfig":
        config_path = Path(path)
        cls.ensure_exists(config_path)
        payload = json.loads(config_path.read_text(encoding="utf-8"))
        changed = cls._populate_generated_defaults(payload)
        if changed:
            config_path.write_text(
                json.dumps(payload, indent=2, sort_keys=False) + "\n",
                encoding="utf-8",
            )
        security_payload = dict(payload.get("security", {}))
        security_payload.pop("enabled", None)
        return cls(
            node_id=str(payload.get("node_id", cls.node_id)),
            long_name=str(payload.get("long_name", cls.long_name)),
            short_name=str(payload.get("short_name", cls.short_name)),
            hw_model=payload.get("hw_model", cls.hw_model),
            role=payload.get("role", cls.role),
            is_licensed=bool(payload.get("is_licensed", cls.is_licensed)),
            hop_limit=int(payload.get("hop_limit", cls.hop_limit)),
            broadcasts=BroadcastConfig(**payload.get("broadcasts", {})),
            position=PositionConfig(**payload.get("position", {})),
            channel=ChannelConfig(**payload.get("channel", {})),
            udp=UdpConfig(**payload.get("udp", {})),
            meshdb=MeshDbConfig(**payload.get("meshdb", {})),
            security=SecurityConfig(**security_payload),
        )

    @staticmethod
    def _example_config_candidates(config_path: Path) -> List[Path]:
        package_root = Path(__file__).resolve().parent
        repo_root = Path(__file__).resolve().parents[2]
        return [
            config_path.with_name("example-node.json"),
            package_root / "example-node.json",
            repo_root / "example-node.json",
        ]

    @classmethod
    def ensure_exists(cls, path: Union[str, Path]) -> None:
        config_path = Path(path)
        if config_path.exists():
            return

        template_path = next(
            (candidate for candidate in cls._example_config_candidates(config_path) if candidate.exists()),
            None,
        )
        if template_path is None:
            raise FileNotFoundError(
                f"Missing config {config_path} and could not find example-node.json to copy from"
            )

        config_path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.loads(template_path.read_text(encoding="utf-8"))
        cls._populate_generated_defaults(payload)
        security = payload.setdefault("security", {})
        security.pop("public_key", None)
        if not str(security.get("private_key", "")).strip():
            from .crypto import b64_encode, generate_keypair

            _public_key, private_key = generate_keypair()
            security["private_key"] = b64_encode(private_key)

        config_path.write_text(
            json.dumps(payload, indent=2, sort_keys=False) + "\n",
            encoding="utf-8",
        )

    @staticmethod
    def _generate_node_id() -> str:
        while True:
            value = secrets.randbits(32)
            if value not in (0, 0xFFFFFFFF):
                return f"!{value:08x}"

    @classmethod
    def _populate_generated_defaults(cls, payload: Dict[str, Any]) -> bool:
        changed = False
        if not str(payload.get("node_id", "")).strip():
            payload["node_id"] = cls._generate_node_id()
            changed = True
        return changed

    def save(self, path: Union[str, Path]) -> None:
        config_path = Path(path)
        config_path.write_text(
            json.dumps(self.to_dict(), indent=2, sort_keys=False) + "\n",
            encoding="utf-8",
        )

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        security = data.get("security")
        if isinstance(security, dict):
            security.pop("public_key", None)
        return data
