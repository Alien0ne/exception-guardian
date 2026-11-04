"""Run independent lookups (plugin CVEs, finding counts, asset context) several at a time, and say how far along a
long run is. One request at a time, a tenant with a few hundred rules sat silent for minutes.

Results come back in input order. A lookup that raises gives its exception in its slot, so each caller keeps its own
per-item warning. The clients retry 429 and 5xx with backoff, so a handful of lookups at once stays polite."""
from __future__ import annotations

import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Iterable, TypeVar

T = TypeVar("T")
R = TypeVar("R")

WORKERS = 8  # lookups in flight at once
PROGRESS_MIN = 20  # fewer lookups than this finish too fast to need a progress line
PROGRESS_EVERY = 2.0  # seconds between progress lines


def parallel_map(fn: Callable[[T], R], items: Iterable[T], label: str = "", workers: int = WORKERS) -> list[R | Exception]:
    items = list(items)
    total = len(items)
    if not total:
        return []
    show = bool(label) and total >= PROGRESS_MIN
    lock, done, last = threading.Lock(), [0], [time.monotonic()]

    def one(x: T) -> R | Exception:
        try:
            return fn(x)
        except Exception as exc:  # the caller turns it into its own warning
            return exc
        finally:
            if show:
                with lock:
                    done[0] += 1
                    now = time.monotonic()
                    if done[0] == total or now - last[0] >= PROGRESS_EVERY:
                        last[0] = now
                        print(f"{label}: {done[0]}/{total}", file=sys.stderr, flush=True)

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        return list(pool.map(one, items))
