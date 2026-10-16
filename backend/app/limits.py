import os
import threading
import time
from collections import deque

from fastapi import HTTPException


_request_windows: dict[str, deque[float]] = {}
_lock = threading.Lock()


def enforce_instance_request_limit(client_key: str) -> None:
    limit = max(1, int(os.getenv("REQUESTS_PER_MINUTE_PER_INSTANCE", "120")))
    now = time.monotonic()
    with _lock:
        window = _request_windows.setdefault(client_key, deque())
        while window and now - window[0] >= 60:
            window.popleft()
        if len(window) >= limit:
            raise HTTPException(status_code=429, detail="Request rate limit exceeded")
        window.append(now)


def enforce_review_quota(review_count: int) -> None:
    limit = max(1, int(os.getenv("MAX_REVIEWS_PER_USER_PER_DAY", "100")))
    if review_count >= limit:
        raise HTTPException(status_code=429, detail="Daily review quota exceeded")
