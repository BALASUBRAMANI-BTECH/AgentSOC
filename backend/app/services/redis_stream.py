import json
import logging
import os
import time
from typing import Any, Dict, List, Optional
from app.models.event import SecurityEvent

logger = logging.getLogger(__name__)

REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))


class RedisStreamService:
    """
    Manages Redis streaming, key counters, and distributed caching.
    Includes in-memory fallback for offline/isolated runtime environments.
    """

    def __init__(self):
        self._connected = False
        self._client = None
        self._memory_counters: Dict[str, dict] = {}
        self._memory_stream: List[dict] = []
        self._init_connection()

    def _init_connection(self):
        try:
            import redis
            from redis.retry import Retry
            from redis.backoff import NoBackoff
            self._client = redis.Redis(
                host=REDIS_HOST,
                port=REDIS_PORT,
                decode_responses=True,
                socket_connect_timeout=0.5,
                socket_timeout=0.5,
                retry=Retry(NoBackoff(), 0),
                retry_on_timeout=False
            )
            if self._client.ping():
                self._connected = True
                logger.info(f"Connected to Redis at {REDIS_HOST}:{REDIS_PORT}")
        except Exception as e:
            self._connected = False
            logger.info(f"Redis offline ({e}). Operating with local in-memory event stream.")

    def publish_event(self, event: SecurityEvent):
        """Pushes security event into Redis event stream."""
        doc = event.model_dump(mode="json")
        self._memory_stream.insert(0, doc)
        if len(self._memory_stream) > 1000:
            self._memory_stream = self._memory_stream[:1000]

        if self._connected and self._client:
            try:
                self._client.lpush("events:stream", json.dumps(doc))
                self._client.ltrim("events:stream", 0, 999)
            except Exception as e:
                logger.debug(f"Redis publish error: {e}")

    def increment_failed_login(self, source_ip: str, window_seconds: int = 300) -> int:
        """Increments sliding-window failed login counter for an IP address."""
        if self._connected and self._client:
            try:
                key = f"failed_logins:{source_ip}"
                count = self._client.incr(key)
                if count == 1:
                    self._client.expire(key, window_seconds)
                return count
            except Exception as e:
                logger.debug(f"Redis incr error: {e}")

        # In-memory fallback counter
        now = time.time()
        record = self._memory_counters.get(source_ip)
        if not record or now > record["expires_at"]:
            self._memory_counters[source_ip] = {"count": 1, "expires_at": now + window_seconds}
            return 1
        record["count"] += 1
        return record["count"]

    def get_failed_logins(self, source_ip: str) -> int:
        """Retrieves active failed login count for an IP address."""
        if self._connected and self._client:
            try:
                val = self._client.get(f"failed_logins:{source_ip}")
                return int(val) if val else 0
            except Exception:
                pass

        now = time.time()
        record = self._memory_counters.get(source_ip)
        if record and now <= record["expires_at"]:
            return record["count"]
        return 0

    def reset_counter(self, source_ip: str):
        """Clears failed login counter for an IP address."""
        if self._connected and self._client:
            try:
                self._client.delete(f"failed_logins:{source_ip}")
            except Exception:
                pass
        self._memory_counters.pop(source_ip, None)


redis_service = RedisStreamService()

