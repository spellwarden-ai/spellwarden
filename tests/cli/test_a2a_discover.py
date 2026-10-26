"""O4 spec 6.3 and claims D1 (discovery part), D2: agent cards are found by name at any depth, after NFC normalisation and case
folding, through the same containment and link rules as every other file; listed cards; the cap of 200; the notices."""
from __future__ import annotations

import json
import os

import pytest
from a2a_cards import card_bytes, clean_card

from spellwarden_cli.discover import MAX_CARDS, CardFile, discover
from spellwarden_cli.files import list_files
from spellwarden_cli.settings import Settings

CARD = card_bytes(clean_card()).decode()


def found(root, **kwargs):
    return discover(list_files(str(root), Settings()), **kwargs)


def forms(result) -> list[tuple[str, str]]:
    return [(card.path, card.path_form) for card in result.agent_cards]


def codes(result) -> list[str]:
    return sorted(notice.code for notice in result.notices)


def test_the_three_names_make_cards_at_any_depth_and_are_not_items(make_repo, tmp_path):
    repo = make_repo(tmp_path / "repo", {
        "public/.well-known/agent-card.json": CARD, ".well-known/agent.json": CARD, "samples/agent-card.json": CARD,
        "deep/er/still/.well-known/agent-card.json": CARD, "agent.json": CARD, "docs/agent-card.json.md": "x",
        "other/.well-known/agentcard.json": CARD})
    result = found(repo)
    assert forms(result) == [
        (".well-known/agent.json", "legacy_path"), ("deep/er/still/.well-known/agent-card.json", "well_known"),
        ("public/.well-known/agent-card.json", "well_known"), ("samples/agent-card.json", "named")]
    assert all(isinstance(card, CardFile) and card.content for card in result.agent_cards)
    assert result.items == () and "no_agent_content" not in codes(result)  # a card is agent content, but not an item


def test_names_are_matched_after_case_folding(make_repo, tmp_path):
    repo = make_repo(tmp_path / "repo", {"A/.Well-Known/Agent-Card.JSON": CARD, "b/AGENT-CARD.json": CARD})
    assert forms(found(repo)) == [("A/.Well-Known/Agent-Card.JSON", "well_known"), ("b/AGENT-CARD.json", "named")]


def test_the_card_content_is_whatever_the_file_holds_even_when_it_is_not_json(make_repo, tmp_path):
    repo = make_repo(tmp_path / "repo", {".well-known/agent-card.json": b'\xef\xbb\xbf{"a": 1,}', "x/agent-card.json": b""})
    assert [(card.path, card.content) for card in found(repo).agent_cards] == [
        (".well-known/agent-card.json", b'\xef\xbb\xbf{"a": 1,}'), ("x/agent-card.json", b"")]


def test_no_agent_content_is_still_noticed_for_a_repository_without_cards_or_agents(make_repo, tmp_path):
    repo = make_repo(tmp_path / "repo", {"README.md": "x"})
    assert "no_agent_content" in codes(found(repo))
    assert "no_agent_content" not in codes(found(repo, agents_configured=True))


def test_listed_cards_are_cards_and_a_listed_path_outside_the_file_set_is_file_missing(make_repo, tmp_path):
    repo = make_repo(tmp_path / "repo", {"deploy/agent/card.json": CARD, "samples/agent-card.json": CARD,
                                         "public/.well-known/agent-card.json": CARD, "a/.well-known/agent.json": CARD})
    result = found(repo, listed_cards=["deploy/agent/card.json", "samples/agent-card.json", "public/.well-known/agent-card.json",
                                       "a/.well-known/agent.json", "nope/card.json", "deploy/agent/card.json"])
    assert forms(result) == [
        ("a/.well-known/agent.json", "listed"), ("deploy/agent/card.json", "listed"),
        ("public/.well-known/agent-card.json", "well_known"), ("samples/agent-card.json", "listed")]
    missing = [(n.code, n.path) for n in result.notices if n.code == "file_missing"]
    assert missing == [("file_missing", "nope/card.json")]


def test_d2_at_most_200_cards_are_read_and_the_notice_counts_the_rest(make_repo, tmp_path):
    files = {f"agents/a{number:03d}/.well-known/agent-card.json": CARD for number in range(201)}
    result = found(make_repo(tmp_path / "repo", files))
    assert len(result.agent_cards) == MAX_CARDS == 200
    assert result.agent_cards[-1].path == "agents/a199/.well-known/agent-card.json"  # path order: the rest are not read
    limit = [n for n in result.notices if n.code == "a2a_cards_limit"]
    assert len(limit) == 1 and limit[0].message.startswith("1 more agent cards were not read")


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symbolic links")
def test_a_link_at_a_card_name_is_followed_inside_the_scan_root_and_refused_outside(make_repo, tmp_path):
    repo = make_repo(tmp_path / "repo", {"real/card.json": CARD})
    (repo / ".well-known").mkdir()
    (repo / ".well-known" / "agent-card.json").symlink_to("../real/card.json")
    outside = tmp_path / "outside.json"
    outside.write_text(CARD)
    (repo / "x").mkdir()
    (repo / "x" / "agent-card.json").symlink_to(outside)
    result = found(repo)
    assert forms(result) == [(".well-known/agent-card.json", "well_known")]
    assert result.agent_cards[0].content == CARD.encode()
    assert [(e.code, e.path) for e in result.errors] == [("unsafe_path", "x/agent-card.json")]


def test_files_the_settings_exclude_are_not_cards(make_repo, tmp_path):
    repo = make_repo(tmp_path / "repo", {"samples/agent-card.json": CARD, "public/.well-known/agent-card.json": CARD})
    result = discover(list_files(str(repo), Settings(exclude=("samples/**",))))
    assert forms(result) == [("public/.well-known/agent-card.json", "well_known")]


def test_other_discovery_is_unchanged_by_the_cards(make_repo, tmp_path):
    files = {".mcp.json": json.dumps({"mcpServers": {"docs": {"url": "https://docs.example.com/mcp"}}}),
             "skills/demo/SKILL.md": "---\nname: demo\ndescription: A demo skill.\n---\n\nRead the task.\n"}
    plain = found(make_repo(tmp_path / "a", files))
    with_card = found(make_repo(tmp_path / "b", {**files, ".well-known/agent-card.json": CARD}))
    assert plain.items == with_card.items and plain.agent_cards == () and len(with_card.agent_cards) == 1
    assert [d.path for d in plain.documents] == [d.path for d in with_card.documents]
