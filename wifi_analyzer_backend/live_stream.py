"""Bounded, site-scoped live event hub and one-use WebSocket tickets."""
from __future__ import annotations

import json
import queue
import re
import secrets
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

SITE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
EVENT_TYPE = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")
TICKET_TTL_SECONDS = 30
MAX_TICKETS = 1_024
MAX_CONNECTIONS = 100
MAX_CONNECTIONS_PER_USER = 5
MAX_SITES_PER_TICKET = 100
MAX_EVENT_BYTES = 16 * 1024
MAX_QUEUED_EVENTS_PER_CLIENT = 64


class LiveStreamCapacityError(RuntimeError):
    """A configured live-stream resource bound has been reached."""


@dataclass(slots=True)
class Ticket:
    token: str
    user_id: str
    session_token: str
    site_ids: frozenset[str]
    expires_at: float


@dataclass(slots=True)
class Client:
    user_id: str
    session_token: str
    site_ids: frozenset[str]
    events: queue.Queue = field(
        default_factory=lambda: queue.Queue(maxsize=MAX_QUEUED_EVENTS_PER_CLIENT)
    )
    closed: threading.Event = field(default_factory=threading.Event)


class LiveStreamHub:
    """In-memory one-use ticket and bounded fan-out hub.

    Tickets never contain authentication credentials in their identifier. The
    associated API session token remains in memory only and is removed when a
    ticket is consumed or expires.
    """

    def __init__(
        self,
        *,
        ticket_ttl_seconds: int = TICKET_TTL_SECONDS,
        max_tickets: int = MAX_TICKETS,
        max_connections: int = MAX_CONNECTIONS,
        max_connections_per_user: int = MAX_CONNECTIONS_PER_USER,
    ):
        if isinstance(ticket_ttl_seconds, bool) or not isinstance(ticket_ttl_seconds, int) or not 5 <= ticket_ttl_seconds <= 120:
            raise ValueError("ticket_ttl_seconds must be from 5 to 120")
        for value, field_name, maximum in (
            (max_tickets, "max_tickets", 100_000),
            (max_connections, "max_connections", 10_000),
            (max_connections_per_user, "max_connections_per_user", 100),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
                raise ValueError(f"{field_name} must be from 1 to {maximum}")
        self.ticket_ttl_seconds = ticket_ttl_seconds
        self.max_tickets = max_tickets
        self.max_connections = max_connections
        self.max_connections_per_user = max_connections_per_user
        self._lock = threading.RLock()
        self._tickets: dict[str, Ticket] = {}
        self._clients: dict[int, Client] = {}
        self._next_client_id = 1

    @staticmethod
    def _sites(site_ids: object) -> frozenset[str]:
        if not isinstance(site_ids, list) or not 1 <= len(site_ids) <= MAX_SITES_PER_TICKET:
            raise ValueError(f"site_ids must contain from 1 to {MAX_SITES_PER_TICKET} sites")
        if any(not isinstance(site, str) or not SITE_ID.fullmatch(site) for site in site_ids):
            raise ValueError("site_ids contains an invalid site identifier")
        if len(site_ids) != len(set(site_ids)):
            raise ValueError("site_ids must be unique")
        return frozenset(site_ids)

    def _prune_tickets(self, now: float) -> None:
        expired = [token for token, ticket in self._tickets.items() if ticket.expires_at <= now]
        for token in expired:
            self._tickets.pop(token, None)

    def issue_ticket(
        self,
        *,
        user_id: str,
        session_token: str,
        site_ids: list[str],
        now: float | None = None,
    ) -> dict:
        if not isinstance(user_id, str) or not user_id or len(user_id) > 64:
            raise ValueError("user_id is invalid")
        if not isinstance(session_token, str) or not session_token:
            raise ValueError("an authenticated session token is required")
        sites = self._sites(site_ids)
        moment = time.time() if now is None else now
        if isinstance(moment, bool) or not isinstance(moment, (int, float)):
            raise ValueError("now must be a finite timestamp")
        with self._lock:
            self._prune_tickets(float(moment))
            if len(self._tickets) >= self.max_tickets:
                raise LiveStreamCapacityError("live-stream ticket capacity has been reached")
            token = secrets.token_urlsafe(32)
            expires = float(moment) + self.ticket_ttl_seconds
            self._tickets[token] = Ticket(
                token=token,
                user_id=user_id,
                session_token=session_token,
                site_ids=sites,
                expires_at=expires,
            )
        return {
            "ticket": token,
            "expires_in_seconds": self.ticket_ttl_seconds,
            "site_ids": sorted(sites),
            "websocket_url": "/ws/live",
            "websocket_protocol": f"wfa-ticket.{token}",
        }

    def consume_ticket(self, token: object, *, now: float | None = None) -> Ticket | None:
        if not isinstance(token, str) or not token or len(token) > 128:
            return None
        moment = time.time() if now is None else now
        if isinstance(moment, bool) or not isinstance(moment, (int, float)):
            return None
        with self._lock:
            self._prune_tickets(float(moment))
            return self._tickets.pop(token, None)

    def register(self, ticket: Ticket) -> tuple[int, Client]:
        if not isinstance(ticket, Ticket):
            raise ValueError("a consumed live-stream ticket is required")
        client = Client(
            user_id=ticket.user_id,
            session_token=ticket.session_token,
            site_ids=ticket.site_ids,
        )
        with self._lock:
            if len(self._clients) >= self.max_connections:
                raise LiveStreamCapacityError("live-stream connection capacity has been reached")
            per_user = sum(item.user_id == client.user_id for item in self._clients.values())
            if per_user >= self.max_connections_per_user:
                raise LiveStreamCapacityError("the user has reached the live-stream connection limit")
            identifier = self._next_client_id
            self._next_client_id += 1
            self._clients[identifier] = client
        return identifier, client

    def unregister(self, identifier: int) -> None:
        with self._lock:
            client = self._clients.pop(identifier, None)
        if client is not None:
            client.closed.set()

    def close_all(self) -> None:
        with self._lock:
            clients = list(self._clients.values())
            self._clients.clear()
            self._tickets.clear()
        for client in clients:
            client.closed.set()

    def publish(
        self,
        event_type: str,
        site_id: str,
        data: dict[str, Any],
        *,
        occurred_at: str | None = None,
    ) -> dict:
        if not isinstance(event_type, str) or not EVENT_TYPE.fullmatch(event_type):
            raise ValueError("event_type is invalid")
        if not isinstance(site_id, str) or not SITE_ID.fullmatch(site_id):
            raise ValueError("site_id is invalid")
        if not isinstance(data, dict):
            raise ValueError("event data must be an object")
        if occurred_at is None:
            occurred_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        if not isinstance(occurred_at, str) or not occurred_at:
            raise ValueError("occurred_at must be a timestamp string")
        event = {
            "type": event_type,
            "site_id": site_id,
            "occurred_at": occurred_at,
            "data": data,
        }
        try:
            encoded = json.dumps(
                event, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                allow_nan=False,
            )
        except (TypeError, ValueError) as error:
            raise ValueError("event must contain finite JSON-compatible values") from error
        if len(encoded.encode("utf-8")) > MAX_EVENT_BYTES:
            raise ValueError(f"event exceeds the {MAX_EVENT_BYTES}-byte live event limit")

        delivered = dropped = 0
        with self._lock:
            clients = list(self._clients.values())
        for client in clients:
            if client.closed.is_set() or site_id not in client.site_ids:
                continue
            try:
                client.events.put_nowait(encoded)
                delivered += 1
            except queue.Full:
                client.closed.set()
                dropped += 1
        return {
            "subscriber_count": delivered + dropped,
            "queued_count": delivered,
            "slow_consumer_count": dropped,
        }

    @property
    def connection_count(self) -> int:
        with self._lock:
            return len(self._clients)

    @property
    def ticket_count(self) -> int:
        with self._lock:
            self._prune_tickets(time.time())
            return len(self._tickets)


LIVE_STREAMS = LiveStreamHub()

__all__ = [
    "Client",
    "EVENT_TYPE",
    "LIVE_STREAMS",
    "LiveStreamCapacityError",
    "LiveStreamHub",
    "MAX_EVENT_BYTES",
    "MAX_QUEUED_EVENTS_PER_CLIENT",
    "Ticket",
]
