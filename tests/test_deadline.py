"""Engine 1.24.0 (speed and deadline spec 7.1, 7.2; claims T9, T10 and T13, and the unit tests of `Meter` and `Lines`): the
`Deadline` a caller builds, the `TimeLimit` that ends a scan, the `Meter` that reads the clock and the `Lines` that tick it once for
each slice of text, never once for each line. Time is a fake clock the test moves: no test here reads the real clock or sleeps."""
from __future__ import annotations

import dataclasses
import math

import pytest
from deadline_clock import Clock

from spellwarden_scan import Deadline, TimeLimit, deadline
from spellwarden_scan.deadline import CHECK_STEP, Lines, Meter
from spellwarden_scan.frontmatter import FrontmatterLimit
from spellwarden_scan.package import TextLimit


def test_after_adds_the_seconds_to_the_reading_of_its_clock():
    clock = Clock(100.0)
    limit = Deadline.after(2.5, clock)
    assert limit.at == 102.5 and limit.clock is clock and clock.reads == 1
    assert not limit.expired()
    clock.now = 102.4
    assert not limit.expired()
    clock.now = 102.5
    assert limit.expired()  # `clock() >= at`


def test_zero_and_negative_seconds_are_a_deadline_that_has_passed_nan_is_an_error_and_infinity_never_expires():
    clock = Clock(10.0)
    assert Deadline.after(0, clock).expired() and Deadline.after(-5, clock).expired()
    assert Deadline.after(-math.inf, clock).expired()
    with pytest.raises(ValueError):
        Deadline.after(math.nan, clock)
    forever = Deadline.after(math.inf, clock)
    clock.now = 1e300
    assert not forever.expired()


def test_a_deadline_is_frozen_hashable_and_the_default_clock_is_the_monotonic_one():
    import time

    limit = Deadline.after(60)
    assert limit.clock is time.monotonic and not limit.expired()
    with pytest.raises(dataclasses.FrozenInstanceError):
        limit.at = 0.0  # type: ignore[misc]
    assert {limit: 1}[limit] == 1 and Deadline(1.0, time.monotonic) == Deadline(1.0)
    assert dataclasses.replace(limit, at=1.0).at == 1.0


def test_time_limit_names_the_stage_and_the_file_and_is_none_of_the_other_limits():
    error = TimeLimit("docs/guide.md", "reading")
    assert (error.path, error.stage) == ("docs/guide.md", "reading")
    assert str(error) == "the time limit was reached while reading docs/guide.md"
    assert str(TimeLimit(None, "judging")) == "the time limit was reached while judging the package"
    assert str(TimeLimit(None, "before")) == "the time limit was reached before the package was read"
    assert str(TimeLimit("a.md", "normalising")) == "the time limit was reached while normalising a.md"
    assert not issubclass(TimeLimit, (TextLimit, FrontmatterLimit, ValueError))
    with pytest.raises(ValueError):
        TimeLimit(None, "afterwards")
    assert deadline.STAGES == ("before", "reading", "normalising", "judging")


def test_a_meter_checks_at_once_and_raises_with_the_stage_it_is_in():
    clock = Clock()
    meter = Meter(Deadline.after(10, clock))
    meter.check("a.md")
    assert meter.stage == "before" and meter.step == CHECK_STEP
    clock.now = 10.0
    with pytest.raises(TimeLimit) as raised:
        meter.check("a.md")
    assert (raised.value.path, raised.value.stage) == ("a.md", "before")
    meter.stage = "judging"
    with pytest.raises(TimeLimit) as raised:
        meter.check()
    assert (raised.value.path, raised.value.stage) == (None, "judging")


def test_a_meter_reads_the_clock_when_step_characters_have_been_counted_and_not_before():
    clock = Clock()
    meter = Meter(Deadline.after(10, clock), step=100)
    reads = clock.reads
    for _ in range(3):
        meter.tick(30, "a.md")
    assert clock.reads == reads and meter.pending == 90
    meter.tick(10, "a.md")  # 100: the step is reached
    assert clock.reads == reads + 1 and meter.pending == 0
    clock.now = 10.0
    meter.tick(99)
    with pytest.raises(TimeLimit) as raised:
        meter.tick(1, "b.md")
    assert raised.value.path == "b.md"


def test_the_default_step_is_read_when_the_meter_is_made(monkeypatch):
    monkeypatch.setattr(deadline, "CHECK_STEP", 7)
    assert Meter(Deadline.after(1, Clock())).step == 7


class CountingMeter(Meter):
    def __init__(self, step: int) -> None:
        super().__init__(Deadline.after(math.inf, Clock()), step)
        self.ticks: list[tuple[int, str | None]] = []

    def tick(self, weight: int, path: str | None = None) -> None:
        self.ticks.append((weight, path))
        super().tick(weight, path)


def test_lines_behave_as_a_tuple_and_len_index_slice_in_and_equality_do_not_tick():
    meter = CountingMeter(5)
    lines = Lines(["abc", "de", "f", "ghijk", ""], meter, "a.md")
    plain = ("abc", "de", "f", "ghijk", "")
    assert len(lines) == 5 and lines[1] == "de" and lines[-1] == "" and "f" in lines
    assert lines == plain and plain == lines and hash(lines) == hash(plain) and lines != plain[:4]
    assert type(lines[1:3]) is tuple and lines[1:3] == ("de", "f") and lines[::2] == ("abc", "f", "")
    assert lines.index("f") == 2 and lines.count("") == 1 and lines + ("z",) == (*plain, "z")
    assert meter.ticks == []


def test_everything_that_iterates_lines_ticks_and_hands_out_the_same_lines():
    plain = ("abc", "de", "f", "ghijk", "l")
    for read in (list, tuple, sorted, lambda lines: [line for line in lines], lambda lines: [line for _, line in enumerate(lines)],
                 lambda lines: [pair[0] for pair in zip(lines, lines, strict=True)], lambda lines: list(map(str, lines))):
        meter = CountingMeter(5)
        read(Lines(plain, meter, "a.md"))
        assert meter.ticks, read
    meter = CountingMeter(5)
    assert "-".join(Lines(plain, meter, "a.md")) == "abc-de-f-ghijk-l" and meter.ticks  # a join iterates, so it can raise TimeLimit
    meter = CountingMeter(5)
    assert list(enumerate(Lines(plain, meter, "a.md"), start=1)) == list(enumerate(plain, start=1))


def test_lines_are_cut_into_slices_that_each_end_at_the_first_line_that_reaches_the_step():
    """T9: one tick for each slice, never one for each line."""
    meter = CountingMeter(5)
    lines = Lines(("abc", "de", "f", "ghijk", "l"), meter, "a.md")
    assert list(lines) == ["abc", "de", "f", "ghijk", "l"]
    assert meter.ticks == [(5, "a.md"), (6, "a.md"), (1, "a.md")]  # "abc"+"de", "f"+"ghijk", then the rest
    meter = CountingMeter(CHECK_STEP)
    short = Lines(tuple(f"line {number}" for number in range(1_000)), meter, "b.md")
    assert len(list(short)) == 1_000
    assert len(meter.ticks) == 1 and meter.ticks[0][0] == sum(len(line) for line in short)  # 1,000 short lines: one tick


def test_the_first_tick_comes_when_the_first_line_is_asked_for_not_when_the_iteration_starts():
    meter = CountingMeter(5)
    iterator = iter(Lines(("abc", "de", "f"), meter, "a.md"))
    assert meter.ticks == []
    assert next(iterator) == "abc" and meter.ticks == [(5, "a.md")]
    assert next(iterator) == "de" and meter.ticks == [(5, "a.md")]  # the same slice
    assert next(iterator) == "f" and meter.ticks == [(5, "a.md"), (1, "a.md")]


def test_the_weights_of_the_slices_add_up_to_the_characters_of_the_lines_and_empty_lines_weigh_nothing():
    meter = CountingMeter(10)
    lines = tuple(["x" * 3, "", "y" * 4, "", "", "z" * 6, "w"] * 20)
    list(Lines(lines, meter, "a.md"))
    assert sum(weight for weight, _ in meter.ticks) == sum(len(line) for line in lines)
    assert all(weight >= 10 for weight, _ in meter.ticks[:-1])
    empty = CountingMeter(1)
    assert list(Lines((), empty, "a.md")) == [] and list(Lines(("", ""), empty, "a.md")) == ["", ""] and empty.ticks == [(0, "a.md")]


def test_once_the_clock_reports_expiry_no_further_line_is_handed_out():
    """T10, for a `Lines`: the lines of the slice whose tick raised are never yielded."""
    clock = Clock()
    meter = Meter(Deadline.after(10, clock), step=4)
    handed = []
    lines = Lines(("aa", "bb", "cc", "dd", "ee", "ff"), meter, "a.md")  # slices: aa+bb, cc+dd, ee+ff
    with pytest.raises(TimeLimit) as raised:
        for line in lines:
            handed.append(line)
            if line == "cc":
                clock.now = 10.0  # the third slice's tick reads the clock after the second slice has been handed out
    assert handed == ["aa", "bb", "cc", "dd"] and (raised.value.path, raised.value.stage) == ("a.md", "before")


def test_a_lines_carries_the_path_it_was_made_for():
    clock = Clock(5.0)
    meter = Meter(Deadline(1.0, clock), step=1)
    with pytest.raises(TimeLimit) as raised:
        list(Lines(("x",), meter, "scripts/run.sh"))
    assert raised.value.path == "scripts/run.sh"
