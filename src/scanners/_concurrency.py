"""Bounded parallel map on top of ``concurrent.futures``."""

from __future__ import annotations

from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from typing import Callable, Iterable, Iterator, TypeVar

T = TypeVar("T")
R = TypeVar("R")


def bounded_map(
    func: Callable[[T], R],
    items: Iterable[T],
    workers: int,
    max_in_flight: int | None = None,
) -> Iterator[R]:
    """Apply ``func`` to ``items`` on a thread pool, yielding results as they finish.

    At most ``max_in_flight`` tasks are queued at once, so enumerating millions
    of files or S3 keys does not build millions of pending futures. Results are
    yielded in completion order, not input order.
    """
    workers = max(1, workers)
    limit = max_in_flight or workers * 4
    iterator = iter(items)
    pending: set[Future[R]] = set()

    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="dcscan") as pool:
        try:
            while True:
                while len(pending) < limit:
                    try:
                        item = next(iterator)
                    except StopIteration:
                        break
                    pending.add(pool.submit(func, item))
                if not pending:
                    return
                done, pending = wait(pending, return_when=FIRST_COMPLETED)
                for future in done:
                    yield future.result()
        finally:
            for future in pending:
                future.cancel()
