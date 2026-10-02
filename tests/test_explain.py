"""
The dictionary, and the sentences it builds.

Two things are checked here that are easy to get subtly wrong: a clustered
short option must expand into every letter it stands for, and a single-dash
long option must never be shredded into one. The rest holds the dictionary
itself to its own shape, so an entry added in a hurry cannot quietly arrive
without a family or with a role that reads like a man page.
"""

import pytest

from caveat.core.explain import (
    COMMANDS,
    DECODERS,
    FETCHERS,
    GENERIC_FLAGS,
    INTERPRETERS,
    SHELLS,
    connector_phrase,
    explain,
    explain_stage,
    gloss_flag,
    info_for,
    is_known,
    kind_of,
    runs_given_text,
)
from caveat.core.lexer import lex


def first(source):
    return lex(source).stages[0]


def sentence(source):
    return explain_stage(first(source)).sentence


# --- the dictionary holds its shape ----------------------------------------

def test_the_dictionary_is_substantial():
    assert len(COMMANDS) >= 60


@pytest.mark.parametrize("name", sorted(COMMANDS))
def test_every_entry_has_a_role_in_plain_words(name):
    info = COMMANDS[name]
    assert info.role, name
    assert info.role[0].islower(), f"{name}: a role is a phrase, not a title"
    assert len(info.role) < 110, name
    assert not info.role.endswith("."), name


@pytest.mark.parametrize("name", sorted(COMMANDS))
def test_every_flag_gloss_is_a_phrase_not_a_sentence(name):
    for flag, meaning in COMMANDS[name].flags.items():
        assert meaning, f"{name} {flag}"
        assert not meaning.endswith("."), f"{name} {flag}"


def test_the_families_are_not_empty():
    assert FETCHERS and SHELLS and INTERPRETERS and DECODERS


def test_curl_and_wget_are_both_fetchers():
    assert {"curl", "wget"} <= FETCHERS


def test_every_shell_runs_what_it_is_given():
    assert all(runs_given_text(name) for name in SHELLS)


def test_an_inspector_does_not_run_what_it_is_given():
    assert not runs_given_text("ls")


# --- lookups ----------------------------------------------------------------

def test_a_known_command_is_found():
    assert is_known("curl") and info_for("curl").role


def test_an_unknown_command_is_reported_as_unknown():
    assert not is_known("frobnicate") and info_for("frobnicate") is None


def test_a_path_resolves_to_the_same_entry():
    assert info_for("/usr/bin/curl") is info_for("curl")


def test_every_mkfs_variant_resolves():
    assert info_for("mkfs.ext4") is info_for("mkfs")
    assert kind_of("mkfs.vfat") == "disk"


def test_a_versioned_python_resolves():
    assert info_for("python3.12") is info_for("python3")


def test_an_empty_command_has_no_entry():
    assert info_for("") is None


# --- flag glossing ----------------------------------------------------------

def test_a_cluster_expands_into_every_letter():
    assert [f for f, _ in gloss_flag("curl", "-fsSL")] == ["-f", "-s", "-S", "-L"]


def test_a_single_dash_long_option_is_not_shredded():
    assert [f for f, _ in gloss_flag("find", "-name")] == ["-name"]


def test_an_exact_entry_beats_a_cluster():
    assert [f for f, _ in gloss_flag("rm", "-rf")] == ["-rf"]


def test_a_cluster_with_one_unknown_letter_is_left_whole():
    assert gloss_flag("ls", "-qzx") == []


def test_an_equals_form_is_glossed_by_its_name():
    assert [f for f, _ in gloss_flag("docker", "--net=host")] == ["--net"]


def test_a_generic_flag_is_used_when_the_command_has_no_entry_of_its_own():
    assert gloss_flag("ls", "-r")[0][1] == GENERIC_FLAGS["-r"]


def test_an_unknown_flag_glosses_to_nothing():
    assert gloss_flag("curl", "--wibble") == []


# --- sentences --------------------------------------------------------------

def test_the_sentence_reads_as_a_sentence():
    assert sentence("curl -sL https://x -o f").startswith(
        "curl — download a URL")


def test_every_glossed_flag_appears_in_the_sentence():
    said = sentence("curl -sL https://x")
    assert "-s silent" in said and "-L follow redirects" in said


def test_a_command_with_no_flags_says_only_its_role():
    assert sentence("whoami") == "whoami — print the user you are running as"


def test_an_unknown_command_says_so_in_the_sentence():
    assert "no entry" in sentence("frobnicate --wibble")


def test_elevation_is_mentioned_in_the_sentence():
    assert "as root" in sentence("sudo rm -rf /tmp/x")


def test_a_subcommand_is_named():
    assert "run start a new container" in sentence("docker run alpine")


def test_key_value_arguments_are_explained():
    said = sentence("dd if=/dev/zero of=/dev/sda")
    assert "of= the DESTINATION" in said


def test_a_truncating_redirect_is_explained():
    assert "output replaces out.txt" in sentence("cmd > out.txt")


def test_an_appending_redirect_is_explained():
    assert "appended to log" in sentence("cmd >> log")


def test_stream_merging_is_explained_as_streams():
    assert "stderr is merged into stdout" in sentence("cmd 2>&1")


def test_explain_covers_nested_stages_too():
    said = explain(lex("bash -c 'rm -rf /tmp/x'"))
    assert [e.command for e in said] == ["bash", "rm"]
    assert said[1].depth == 1 and said[1].origin


def test_an_explanation_records_whether_it_was_known():
    assert explain_stage(first("ls")).known is True
    assert explain_stage(first("frobnicate")).known is False


# --- connectors -------------------------------------------------------------

@pytest.mark.parametrize("connector,phrase", [
    ("|", "stdout"),
    ("&&", "if it succeeds"),
    ("||", "if it fails"),
    (";", "then"),
    ("\n", "then"),
    ("", ""),
])
def test_each_connector_has_a_plain_english_phrase(connector, phrase):
    assert connector_phrase(connector) == phrase
