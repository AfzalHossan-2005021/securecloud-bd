from __future__ import annotations

from pydantic import BaseModel, Field, model_validator
from typing import Annotated


FEATURE_NAMES = [
    "duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts",
    "orig_ip_bytes", "resp_ip_bytes", "missed_bytes",
    "proto_tcp", "proto_udp", "proto_icmp",
    "conn_state_S0", "conn_state_SF", "conn_state_REJ", "conn_state_RSTO",
    "service_http", "service_dns", "service_ssl",
    "bytes_per_pkt_orig", "bytes_per_pkt_resp",
]

N_FEATURES = len(FEATURE_NAMES)


class FlowFeatures(BaseModel):
    """Single network-flow feature vector."""
    duration: float = Field(ge=0)
    orig_bytes: float = Field(ge=0)
    resp_bytes: float = Field(ge=0)
    orig_pkts: float = Field(ge=0)
    resp_pkts: float = Field(ge=0)
    orig_ip_bytes: float = Field(ge=0)
    resp_ip_bytes: float = Field(ge=0)
    missed_bytes: float = Field(ge=0)
    proto_tcp: Annotated[float, Field(ge=0, le=1)] = 0.0
    proto_udp: Annotated[float, Field(ge=0, le=1)] = 0.0
    proto_icmp: Annotated[float, Field(ge=0, le=1)] = 0.0
    conn_state_S0: Annotated[float, Field(ge=0, le=1)] = 0.0
    conn_state_SF: Annotated[float, Field(ge=0, le=1)] = 0.0
    conn_state_REJ: Annotated[float, Field(ge=0, le=1)] = 0.0
    conn_state_RSTO: Annotated[float, Field(ge=0, le=1)] = 0.0
    service_http: Annotated[float, Field(ge=0, le=1)] = 0.0
    service_dns: Annotated[float, Field(ge=0, le=1)] = 0.0
    service_ssl: Annotated[float, Field(ge=0, le=1)] = 0.0
    bytes_per_pkt_orig: float = Field(ge=0, default=0.0)
    bytes_per_pkt_resp: float = Field(ge=0, default=0.0)

    def to_array(self) -> list[float]:
        return [getattr(self, f) for f in FEATURE_NAMES]


class ScoreRequest(BaseModel):
    flows: list[FlowFeatures] = Field(min_length=1, max_length=10_000)


class FlowScore(BaseModel):
    score: float
    is_anomaly: bool


class ScoreResponse(BaseModel):
    results: list[FlowScore]
    anomaly_count: int
    anomaly_rate: float
    model_version: str


class HealthResponse(BaseModel):
    status: str
    model_loaded: bool
    model_version: str
