"""P6-15 spec 6.12 E-9: scripts/check-rule-pages.py, which the release workflow runs before it publishes, fails unless every
baseline rule's page answers 200 itself with the rule id in its body. Checked offline here with a stand-in for the network."""
from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("check_rule_pages", ROOT / "scripts" / "check-rule-pages.py")
check = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(check)


def test_it_lists_the_page_of_every_baseline_rule():
    listed = check.pages()
    assert len(listed) == 69
    assert ("SW-SKL-009", "https://spellwarden.ai/docs/rules/sw-skl-009") in listed
    assert all(page == f"https://spellwarden.ai/docs/rules/{rule_id.lower()}" for rule_id, page in listed)


def test_a_page_must_answer_200_with_its_rule_id():
    answers = {"https://p/a": (200, "<h1>SW-SKL-001</h1>"), "https://p/b": (200, "<h1>Page not found</h1>"),
               "https://p/c": (301, ""), "https://p/d": (404, "")}

    def get(url: str) -> tuple[int, str]:
        if url == "https://p/e":
            raise TimeoutError("timed out")
        return answers[url]

    pages = [("SW-SKL-001", "https://p/a"), ("SW-SKL-002", "https://p/b"), ("SW-SKL-003", "https://p/c"),
             ("SW-SKL-004", "https://p/d"), ("SW-SKL-005", "https://p/e")]
    assert check.problems(pages, get) == [
        "SW-SKL-002: https://p/b answered 200 without the rule id in its body",
        "SW-SKL-003: https://p/c answered 301, not 200",
        "SW-SKL-004: https://p/d answered 404, not 200",
        "SW-SKL-005: https://p/e could not be read (TimeoutError)"]
    assert check.problems(pages[:1], get) == []


def test_main_says_how_many_pages_answer(monkeypatch, capsys):
    monkeypatch.setattr(check, "problems", lambda _listed: [])
    assert check.main() == 0
    assert capsys.readouterr().out == "69 of 69 rule pages answer\n"
    monkeypatch.setattr(check, "problems", lambda _listed: ["SW-SKL-001: x answered 404, not 200"])
    assert check.main() == 1
    captured = capsys.readouterr()
    assert captured.out == "68 of 69 rule pages answer\n" and captured.err == "SW-SKL-001: x answered 404, not 200\n"
