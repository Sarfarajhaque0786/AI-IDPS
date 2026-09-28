from sqlalchemy import (
    Column, Integer, String, DateTime, Float, Boolean, ForeignKey, Text, Index
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.database.connection import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    role = Column(String, default="VIEWER", nullable=False)  # ADMIN | VIEWER
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class TrafficEvent(Base):
    __tablename__ = "traffic_events"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    source_ip = Column(String, nullable=False)
    destination_ip = Column(String, nullable=True)
    source_port = Column(Integer, nullable=True)
    destination_port = Column(Integer, nullable=True)
    protocol = Column(String, nullable=True)
    packet_count = Column(Integer, default=0)
    byte_count = Column(Integer, default=0)

    attack_type = Column(String, default="BENIGN")       # BENIGN, DoS, Probe, Brute Force, Bot, Web Attack, Other
    detection_method = Column(String, nullable=True)      # RULE, ML, HYBRID
    confidence = Column(Float, nullable=True)              # 0.0 - 1.0
    severity = Column(String, default="LOW")               # LOW, MEDIUM, HIGH, CRITICAL
    status = Column(String, default="NEW")                 # NEW, REVIEWED, IGNORED

    alerts = relationship("Alert", back_populates="event")
    prevention_actions = relationship("PreventionAction", back_populates="event")

    __table_args__ = (
        Index("ix_traffic_events_timestamp", "timestamp"),
        Index("ix_traffic_events_source_ip", "source_ip"),
        Index("ix_traffic_events_attack_type", "attack_type"),
        Index("ix_traffic_events_severity", "severity"),
        Index("ix_traffic_events_status", "status"),
    )


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(Integer, ForeignKey("traffic_events.id"), nullable=False)
    severity = Column(String, nullable=False)
    attack_type = Column(String, nullable=False)
    message = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    status = Column(String, default="NEW")  # NEW, ACKNOWLEDGED, RESOLVED, FALSE_POSITIVE

    event = relationship("TrafficEvent", back_populates="alerts")

    __table_args__ = (
        Index("ix_alerts_severity", "severity"),
        Index("ix_alerts_status", "status"),
        Index("ix_alerts_created_at", "created_at"),
    )


class PreventionAction(Base):
    __tablename__ = "prevention_actions"

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(Integer, ForeignKey("traffic_events.id"), nullable=False)
    action = Column(String, nullable=False)   # BLOCK, QUARANTINE, RATE_LIMIT, DISABLE_SESSION
    target = Column(String, nullable=False)
    reason = Column(Text, nullable=True)
    executed_at = Column(DateTime(timezone=True), server_default=func.now())
    status = Column(String, default="SUCCESS")  # SUCCESS, FAILED

    event = relationship("TrafficEvent", back_populates="prevention_actions")


class BlockedSource(Base):
    __tablename__ = "blocked_sources"

    id = Column(Integer, primary_key=True, index=True)
    source_identifier = Column(String, nullable=False, index=True)
    reason = Column(Text, nullable=True)
    severity = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=True)
    is_active = Column(Boolean, default=True)


class ModelVersion(Base):
    __tablename__ = "model_versions"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    algorithm = Column(String, nullable=False)     # e.g. RandomForestClassifier
    version = Column(String, nullable=False)
    accuracy = Column(Float, nullable=True)
    precision = Column(Float, nullable=True)
    recall = Column(Float, nullable=True)
    f1_score = Column(Float, nullable=True)
    trained_at = Column(DateTime(timezone=True), server_default=func.now())
    model_path = Column(String, nullable=False)
    is_active = Column(Boolean, default=False)