"""ORM models: users, alerts, cases (+notes, actions, chat), assets, vulnerabilities, audit log."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Table, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


def utcnow() -> datetime:
    """Naive UTC timestamp (portable across SQLite and PostgreSQL)."""
    return datetime.now(UTC).replace(tzinfo=None)


case_alerts = Table(
    "case_alerts",
    Base.metadata,
    Column("case_id", ForeignKey("cases.id", ondelete="CASCADE"), primary_key=True),
    Column("alert_id", ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True),
)


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    full_name: Mapped[str] = mapped_column(String(128), default="")
    role: Mapped[str] = mapped_column(String(16), default="analyst")  # admin | analyst | viewer
    password_hash: Mapped[str] = mapped_column(String(256))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Alert(Base):
    __tablename__ = "alerts"
    id: Mapped[int] = mapped_column(primary_key=True)
    external_id: Mapped[str] = mapped_column(String(128), default="", index=True)
    source: Mapped[str] = mapped_column(String(32), default="generic", index=True)
    title: Mapped[str] = mapped_column(String(512))
    description: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(16), default="medium", index=True)
    status: Mapped[str] = mapped_column(String(16), default="new", index=True)
    category: Mapped[str] = mapped_column(String(128), default="")
    host: Mapped[str] = mapped_column(String(255), default="", index=True)
    username: Mapped[str] = mapped_column(String(255), default="", index=True)
    src_ip: Mapped[str] = mapped_column(String(64), default="", index=True)
    dst_ip: Mapped[str] = mapped_column(String(64), default="", index=True)
    raw: Mapped[Any] = mapped_column(JSON, default=dict)
    iocs: Mapped[Any] = mapped_column(JSON, default=list)
    enrichment: Mapped[Any] = mapped_column(JSON, default=dict)
    mitre: Mapped[Any] = mapped_column(JSON, default=list)
    risk_score: Mapped[int] = mapped_column(Integer, default=0, index=True)
    verdict: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    ai_report: Mapped[Any | None] = mapped_column(JSON, nullable=True)
    event_time: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)

    cases: Mapped[list[Case]] = relationship(secondary=case_alerts, back_populates="alerts")


class Case(Base):
    __tablename__ = "cases"
    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(String(512))
    summary: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(16), default="medium")
    status: Mapped[str] = mapped_column(String(16), default="open", index=True)
    assignee: Mapped[str] = mapped_column(String(64), default="")
    ai_report: Mapped[Any | None] = mapped_column(JSON, nullable=True)
    created_by: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    alerts: Mapped[list[Alert]] = relationship(secondary=case_alerts, back_populates="cases")
    notes: Mapped[list[CaseNote]] = relationship(
        back_populates="case", cascade="all, delete-orphan", order_by="CaseNote.id"
    )
    actions: Mapped[list[ResponseAction]] = relationship(
        back_populates="case", cascade="all, delete-orphan", order_by="ResponseAction.id"
    )
    chat: Mapped[list[ChatMessage]] = relationship(
        back_populates="case", cascade="all, delete-orphan", order_by="ChatMessage.id"
    )


class CaseNote(Base):
    __tablename__ = "case_notes"
    id: Mapped[int] = mapped_column(primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    author: Mapped[str] = mapped_column(String(64))
    content: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    case: Mapped[Case] = relationship(back_populates="notes")


class ResponseAction(Base):
    __tablename__ = "response_actions"
    id: Mapped[int] = mapped_column(primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    action: Mapped[str] = mapped_column(String(32))
    target: Mapped[str] = mapped_column(String(512))
    performed_by: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16), default="simulated")
    details: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    case: Mapped[Case] = relationship(back_populates="actions")


class ChatMessage(Base):
    __tablename__ = "chat_messages"
    id: Mapped[int] = mapped_column(primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    role: Mapped[str] = mapped_column(String(16))  # user | assistant
    content: Mapped[str] = mapped_column(Text)
    author: Mapped[str] = mapped_column(String(64), default="")
    engine: Mapped[str] = mapped_column(String(32), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    case: Mapped[Case] = relationship(back_populates="chat")


class Asset(Base):
    __tablename__ = "assets"
    id: Mapped[int] = mapped_column(primary_key=True)
    hostname: Mapped[str] = mapped_column(String(255), default="", index=True)
    ip: Mapped[str] = mapped_column(String(64), default="", index=True)
    os: Mapped[str] = mapped_column(String(255), default="")
    criticality: Mapped[str] = mapped_column(String(16), default="medium")
    owner: Mapped[str] = mapped_column(String(128), default="")
    open_ports: Mapped[Any] = mapped_column(JSON, default=list)
    last_scanned: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    vulnerabilities: Mapped[list[Vulnerability]] = relationship(back_populates="asset", cascade="all, delete-orphan")


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    title: Mapped[str] = mapped_column(String(512))
    cve: Mapped[str] = mapped_column(String(32), default="", index=True)
    cvss: Mapped[float] = mapped_column(Float, default=0.0)
    severity: Mapped[str] = mapped_column(String(16), default="low")
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    service: Mapped[str] = mapped_column(String(64), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    remediation: Mapped[str] = mapped_column(Text, default="")
    exploit_available: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[str] = mapped_column(String(16), default="open", index=True)
    source: Mapped[str] = mapped_column(String(16), default="manual")
    priority_score: Mapped[float] = mapped_column(Float, default=0.0, index=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)

    asset: Mapped[Asset] = relationship(back_populates="vulnerabilities")


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[int] = mapped_column(primary_key=True)
    actor: Mapped[str] = mapped_column(String(64), index=True)
    action: Mapped[str] = mapped_column(String(64), index=True)
    entity: Mapped[str] = mapped_column(String(32), default="")
    entity_id: Mapped[str] = mapped_column(String(64), default="")
    details: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
