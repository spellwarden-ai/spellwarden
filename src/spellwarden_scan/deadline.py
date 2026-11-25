"""Engine 1.24.0 (speed and deadline spec 7): the time limit of a scan. `Deadline` is an absolute reading of a monotonic clock
that the caller builds once and shares across every package of a scan; `TimeLimit` is what `scan_skill_package(...,
deadline=...)` raises when the clock reaches it, with no partial result: content the scan leaves unread never looks like a pass.
`Meter` and `Lines` are the engine's own way of looking at the clock: `Lines` is a tuple of lines that counts the characters it
hands out and reads the clock once for every `CHECK_STEP` of them, so a rule that loops over lines meets the deadline without a
line of its own. The clock is a function the caller can replace; the default is `time.monotonic`. The engine never sleeps."""
from __future__ import annotations

import bisect
import itertools
import math
import time
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass

CHECK_STEP = 64 * 1024  # characters of line text between two clock reads
STAGES = ("before", "reading", "normalising", "judging")


@dataclass(frozen=True)
class Deadline:
    """`at` is an absolute reading of `clock`. Immutable and hashable, so one value serves every package of a scan and every
    thread. `Deadline.after(seconds)` is the usual way to make one."""

    at: float
    clock: Callable[[], float] = time.monotonic

    @classmethod
    def after(cls, seconds: float, clock: Callable[[], float] = time.monotonic) -> Deadline:
        """The deadline `seconds` from now by `clock`. Zero or less is a deadline that has already passed, infinity never
        expires; `nan` is a `ValueError`."""
        if math.isnan(seconds):
            raise ValueError("seconds must be a number, not nan")
        return cls(clock() + seconds, clock)

    def expired(self) -> bool:
        return self.clock() >= self.at


class TimeLimit(Exception):
    """The scan's time limit was reached before the package was judged. Nothing is returned for that package: the findings
    gathered so far are dropped with it. `path` is the file being read when the limit was reached, None when it was reached
    between files, views or rules; `stage` is `before` (the deadline had passed when the call began), `reading` (building the
    package), `normalising` (building the normalised views) or `judging` (the rules)."""

    def __init__(self, path: str | None, stage: str) -> None:
        if stage not in STAGES:
            raise ValueError(f"stage must be one of {', '.join(STAGES)}, not {stage!r}")
        if stage == "before":
            where = "before the package was read"
        else:
            where = f"while {stage} {'the package' if path is None else path}"
        super().__init__(f"the time limit was reached {where}")
        self.path = path
        self.stage = stage


class Meter:
    """One per call of `scan_skill_package` that has a deadline. `tick(weight)` adds the characters a rule is about to read and
    reads the clock when `step` of them have been counted since the last read; `check()` reads it at once. Both raise `TimeLimit`
    when the deadline has passed, with the `stage` the scan is in. `step` is `CHECK_STEP` read when the meter is made."""

    def __init__(self, deadline: Deadline, step: int | None = None) -> None:
        self.deadline = deadline
        self.step = CHECK_STEP if step is None else step
        self.stage = "before"
        self.pending = 0

    def check(self, path: str | None = None) -> None:
        self.pending = 0
        if self.deadline.expired():
            raise TimeLimit(path, self.stage)

    def tick(self, weight: int, path: str | None = None) -> None:
        self.pending += weight
        if self.pending >= self.step:
            self.check(path)


CUT_BLOCK = 8192  # lines whose running totals `_cuts` holds at once, so that a file of millions of lines costs a bounded list


def _cuts(lines: tuple[str, ...] | list[str], step: int) -> tuple[tuple[int, int, int], ...]:
    """The slices a `Lines` hands out, `(start, end, weight)`: a slice ends at the first line that brings its characters to `step`
    or more, and the last one holds the rest. The lengths are summed and searched in C a block of lines at a time; Python runs
    once for each slice, not once for each line. Most calls are for a few lines that never reach `step`: one sum answers those."""
    total = sum(map(len, lines))
    if total < step:
        return ((0, len(lines), total),) if lines else ()
    cuts: list[tuple[int, int, int]] = []
    start = held = 0  # held: the characters of the lines from `start` to the block's start
    for block_start in range(0, len(lines), CUT_BLOCK):
        running = list(itertools.accumulate(map(len, lines[block_start:block_start + CUT_BLOCK])))
        base = position = 0  # the running total before `position`'s slice, and where the search goes on
        while True:
            at = bisect.bisect_left(running, base + step - held, position)
            if at == len(running):
                held += running[-1] - base
                break
            end = block_start + at + 1
            cuts.append((start, end, held + running[at] - base))
            start, held, base, position = end, 0, running[at], at + 1
    if start < len(lines):
        cuts.append((start, len(lines), held))
    return tuple(cuts)


class Lines(tuple):
    """A tuple of lines that ticks a `Meter` as it is iterated: once for each slice of about `meter.step` characters, never once
    for each line, and its lines are handed out by `itertools.chain`, in C. `len`, indexing, slicing (a plain tuple), `in`,
    equality and hashing behave as for a tuple and do not tick; whatever iterates it does: `for`, `join`, `tuple`, `list`,
    `enumerate`, `zip`, `sorted`. Make it from a plain tuple or list, never from another `Lines`."""

    def __new__(cls, lines: Iterable[str], meter: Meter, path: str | None) -> Lines:
        if not isinstance(lines, (tuple, list)):
            lines = tuple(lines)
        self = super().__new__(cls, lines)
        total = sum(map(len, lines))
        # the common case, a few lines that never reach the step, needs no cut: one tick of all their characters, `cuts` is None
        small = 0 < len(lines) and total < meter.step
        self._state = (meter, path, total, None if small else _cuts(lines, meter.step))
        return self

    def _slices(self, cuts: tuple[tuple[int, int, int], ...]) -> Iterator[tuple[str, ...]]:
        meter, path = self._state[:2]
        for start, end, weight in cuts:
            meter.tick(weight, path)
            yield tuple.__getitem__(self, slice(start, end))

    def __iter__(self) -> Iterator[str]:
        meter, path, total, cuts = self._state
        if cuts is None:  # a few lines that never reach the step: one tick, then the lines as a tuple hands them out
            meter.tick(total, path)
            return tuple.__iter__(self)
        return itertools.chain.from_iterable(self._slices(cuts))
