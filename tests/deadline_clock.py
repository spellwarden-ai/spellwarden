"""Fakes for the tests of the deadline (engine 1.24.0, speed and deadline spec 11.2): a clock the test moves, and a files mapping
that moves it when the scan reads a named file. Nothing here reads the real clock or sleeps."""
from __future__ import annotations


class Clock:
    """A clock that is where the test puts it (`now`) and counts how often it is read (`reads`). With `expire_after=n` it reports
    `then` from the (n + 1)th read on, whatever `now` says: the tests use it to make a deadline pass at a chosen place."""

    def __init__(self, now: float = 0.0, *, expire_after: int | None = None, then: float = 1e9) -> None:
        self.now = now
        self.expire_after = expire_after
        self.then = then
        self.reads = 0

    def __call__(self) -> float:
        self.reads += 1
        if self.expire_after is not None and self.reads > self.expire_after:
            return self.then
        return self.now


class Expiring(dict):
    """`{path: bytes}` that moves `clock` to `then` when `key` is read, and records every path read in `reads`."""

    def __init__(self, files: dict[str, bytes], clock: Clock, key: str, then: float = 1e9) -> None:
        super().__init__(files)
        self.clock, self.key, self.then = clock, key, then
        self.reads: list[str] = []

    def __getitem__(self, path: str) -> bytes:
        self.reads.append(path)
        if path == self.key:
            self.clock.now = self.then
        return super().__getitem__(path)
