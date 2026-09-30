"""Bounded parallel map on top of ``concurrent.futures``."""

from __future__ import annotations

import multiprocessing
from concurrent.futures import (
    FIRST_COMPLETED,
    Executor,
    Future,
    ProcessPoolExecutor,
    ThreadPoolExecutor,
    wait,
)
from typing import Any, Callable, Iterable, Iterator, TypeVar

T = TypeVar("T")
R = TypeVar("R")


def bounded_map(
    func: Callable[[T], R],
    items: Iterable[T],
    workers: int,
    max_in_flight: int | None = None,
    *,
    processes: bool = False,
    initializer: Callable[..., None] | None = None,
    initargs: tuple[Any, ...] = (),
) -> Iterator[R]:
    """Apply ``func`` to ``items`` on a pool, yielding results as they finish.

    At most ``max_in_flight`` tasks are queued at once, so enumerating millions
    of files or S3 keys does not build millions of pending futures. Results are
    yielded in completion order, not input order.

    Threads are the default (right for I/O-bound sources). ``processes=True``
    uses a spawn-based process pool, which is the way to use several cores for
    CPU-bound pattern matching; ``func`` and ``initializer`` must then be
    importable module-level callables and every argument picklable.
    """
    workers = max(1, workers)
    limit = max_in_flight or workers * 4
    iterator = iter(items)
    pending: set[Future[R]] = set()

    pool: Executor
    if processes:
        pool = ProcessPoolExecutor(
            max_workers=workers,
            mp_context=multiprocessing.get_context("spawn"),
            initializer=initializer,
            initargs=initargs,
        )
    else:
        pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="dcscan")

    with pool:
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
