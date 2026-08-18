import json
import logging
from collections.abc import Callable
from typing import Any

from redis import Redis
from redis.exceptions import RedisError

from app.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

cache_client = Redis.from_url(settings.redis_url, decode_responses=True)


def cached_json(key: str, ttl: int, producer: Callable[[], Any]) -> Any:
    try:
        raw = cache_client.get(key)
        if raw is not None:
            return json.loads(raw)
    except (RedisError, json.JSONDecodeError):
        logger.warning("Lecture cache echouee pour %s", key)

    value = producer()

    try:
        cache_client.setex(key, ttl, json.dumps(value, default=str))
    except RedisError:
        logger.warning("Ecriture cache echouee pour %s", key)

    return value


def invalidate(pattern: str) -> None:
    try:
        for key in cache_client.scan_iter(match=pattern, count=100):
            cache_client.delete(key)
    except RedisError:
        logger.warning("Invalidation cache echouee pour %s", pattern)
