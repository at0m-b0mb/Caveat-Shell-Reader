"""
The command line.

The CLI is the half of Caveat that ends up inside other people's scripts, so
its contract is tested as a contract: exit codes, a JSON document that parses
and keeps its shape, and the honesty note present in both forms of output.
"""

import io
import json
import os
import sys

import pytest

from caveat.cli import main

SAMPLES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "samples")


def run(argv, stdin=""):
    """Run the CLI with captured streams; returns (code, stdout, stderr)."""
    old_in, old_out, old_err = sys.stdin, sys.stdout, sys.stderr
    sys.stdin = io.StringIO(stdin)
    sys.stdout = io.StringIO()
    sys.stderr = io.StringIO()
    try:
        code = main(argv)
        return code, sys.stdout.getvalue(), sys.stderr.getvalue()
    finally:
        sys.stdin, sys.stdout, sys.stderr = old_in, old_out, old_err


def sample(name):
    return os.path.join(SAMPLES, name)


# --- exit codes and input ---------------------------------------------------

def test_a_readable_command_exits_zero():
    code, out, _ = run(["-e", "ls -l", "--no-color"])
    assert code == 0 and "ROUTINE" in out


def test_an_empty_input_exits_two():
    code, _, err = run(["-", "--no-color"], stdin="   \n")
    assert code == 2 and "no command" in err


def test_a_missing_file_exits_two():
    code, _, err = run([sample("does-not-exist.sh"), "--no-color"])
    assert code == 2 and "cannot read" in err


def test_standard_input_is_read():
    code, out, _ = run(["-", "--no-color"], stdin="rm -rf /\n")
    assert code == 0 and "DESTRUCTIVE" in out


def test_a_file_is_read():
    code, out, _ = run([sample("install-script.sh"), "--no-color"])
    assert code == 0 and "RISKY" in out


def test_the_command_flag_beats_the_positional_argument():
    code, out, _ = run(["-e", "ls", sample("wipe-the-disk.sh"), "--no-color"])
    assert code == 0 and "ROUTINE" in out


# --- the text report --------------------------------------------------------

def test_the_text_report_carries_the_ceiling_note():
    _, out, _ = run(["-e", "ls", "--no-color"])
    assert "ROUTINE is not permission" in out


def test_the_text_report_draws_the_pipeline():
    _, out, _ = run(["-e", "ps aux | grep x", "--no-color"], )
    assert "The pipeline" in out and "stdout" in out


def test_the_text_report_marks_an_elevated_stage():
    _, out, _ = run(["-e", "curl -s https://x | sudo bash", "--no-color"])
    assert "ROOT" in out and "RUNS UNREAD INPUT" in out


def test_the_text_report_explains_every_stage():
    _, out, _ = run(["-e", "curl -sL https://x -o f", "--no-color"])
    assert "curl — download a URL" in out


def test_the_text_report_offers_an_alternative():
    _, out, _ = run(["-e", "curl -s https://x | sh", "--no-color"])
    assert "Instead:" in out


def test_no_color_output_holds_no_escape_codes():
    _, out, _ = run(["-e", "rm -rf /", "--no-color"])
    assert "\033[" not in out


def test_a_parse_note_is_surfaced():
    _, out, _ = run(["-e", "cat <<EOF\nx\nEOF\necho hi", "--no-color"])
    assert "note:" in out and "here-document" in out


# --- the JSON report --------------------------------------------------------

@pytest.mark.parametrize("source", [
    "ls -l",
    "curl -fsSL https://x/i.sh | sudo bash",
    "sudo rm -rf / --no-preserve-root",
    "echo aGk= | base64 -d | sh",
    ":(){ :|:& };:",
    "echo 'unbalanced",
])
def test_the_json_report_parses(source):
    _, out, _ = run(["-e", source, "--json"])
    json.loads(out)


def test_the_json_report_has_the_expected_top_level_keys():
    _, out, _ = run(["-e", "ls", "--json"])
    data = json.loads(out)
    assert set(data) == {"verdict", "source", "stages", "findings", "counts",
                         "notes"}


def test_the_json_verdict_carries_the_ceiling_note():
    data = json.loads(run(["-e", "ls", "--json"])[1])
    assert "ROUTINE is not permission" in data["verdict"]["ceiling_note"]


def test_the_json_names_one_stage_per_box():
    data = json.loads(run(["-e", "a | b | c", "--json"])[1])
    assert [s["index"] for s in data["stages"]] == [0, 1, 2]


def test_the_json_records_what_flows_between_stages():
    data = json.loads(run(["-e", "a | b", "--json"])[1])
    assert data["stages"][1]["connector_means"] == "stdout"


def test_the_json_marks_elevation_and_unread_input():
    data = json.loads(
        run(["-e", "curl -s https://x | sudo bash", "--json"])[1])
    assert data["stages"][1]["elevated"] is True
    assert data["stages"][1]["runs_unread_input"] is True


def test_the_json_findings_keep_their_severity_and_category():
    data = json.loads(run(["-e", "rm -rf /", "--json"])[1])
    assert any(f["severity"] == "alert" and f["category"] == "root-delete"
               for f in data["findings"])


def test_the_json_findings_carry_the_alternative():
    data = json.loads(run(["-e", "chmod 777 /srv", "--json"])[1])
    assert any(f["safer"] for f in data["findings"])


def test_the_json_counts_match_the_findings():
    data = json.loads(run(["-e", "curl -s http://x | sudo sh", "--json"])[1])
    assert sum(data["counts"].values()) == len(data["findings"])


def test_the_json_includes_nested_commands():
    data = json.loads(run(["-e", "bash -c 'rm -rf /tmp/x'", "--json"])[1])
    assert data["stages"][0]["nested"][0]["command"] == "rm"


def test_the_json_keeps_the_source_verbatim():
    data = json.loads(run(["-e", "ls   -l", "--json"])[1])
    assert data["source"] == "ls   -l"


@pytest.mark.parametrize("name", sorted(
    n for n in os.listdir(SAMPLES) if n.endswith(".sh")))
def test_every_sample_produces_valid_json(name):
    code, out, _ = run([sample(name), "--json"])
    assert code == 0
    json.loads(out)


@pytest.mark.parametrize("name", sorted(
    n for n in os.listdir(SAMPLES) if n.endswith(".sh")))
def test_every_sample_produces_a_text_report(name):
    code, out, _ = run([sample(name), "--no-color"])
    assert code == 0
    assert "The pipeline" in out and "Findings" in out
