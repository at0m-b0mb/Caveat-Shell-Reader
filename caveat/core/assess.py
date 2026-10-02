"""
The verdict — four words, and the limits of all four.

A command line is not a score out of a hundred, so Caveat does not give it one.
It gives one of four words, and the rule for choosing between them is short
enough to hold in your head:

* **DESTRUCTIVE** — something here removes data that does not come back: the
  filesystem root, a whole home directory, a raw disk write, a fork bomb.
* **RISKY** — something here runs code nobody has read, or opens a way in, or
  hands root its instructions from somewhere else.
* **WORTH A LOOK** — a real hazard, *or* a gap in what Caveat can know.
* **ROUTINE** — nothing matched, every command was recognised, and the line
  parsed cleanly.

The third of those carries the honesty ceiling, and it is the most important
line of code in the project: **unknown beats a guess.** A line containing one
command Caveat has never heard of cannot be ROUTINE, because "nothing matched"
would then mean "nothing was looked at". The same applies to a line whose quotes
do not close, and to one whose first word is a variable.

ROUTINE is not permission. It means nothing in Caveat's register matched the
text — not that the line is safe, not that it does what its sender says, and
not that it is a good idea on your machine. Caveat reads text. It never runs,
simulates or fetches anything, so it cannot know what your aliases and PATH
will turn these words into, what a server will send when the line is run, or
what the files on your machine are worth to you. The last of those is the only
question that actually decides whether a command is dangerous, and it is the
one question a program cannot answer.
"""

from __future__ import annotations

from .explain import explain, explain_stage, is_known, runs_given_text
from .lexer import lex
from .model import (
    Reading,
    Script,
    Severity,
    StageView,
    Verdict,
    worse,
)
from .rules import is_function_definition, locally_defined
from .rules import run as run_rules

CEILING_NOTE = (
    "Caveat reads the text of this command and nothing else. It never runs, "
    "simulates or fetches anything, so it cannot know what your aliases, shell "
    "functions or PATH will turn these words into, what a remote script will "
    "contain when it is fetched, or what the data on your machine is worth. "
    "ROUTINE is not permission — it means nothing matched, and the "
    "responsibility is still yours."
)

HEADLINES = {
    Verdict.ROUTINE: "Nothing in this line matched a risk pattern",
    Verdict.WORTH_A_LOOK: "A few things here are worth understanding first",
    Verdict.RISKY: "This line does something you should not run on trust",
    Verdict.DESTRUCTIVE: "This can destroy data that does not come back",
}

# The categories whose ALERT findings mean irreversible loss rather than
# exposure. Everything else at ALERT is RISKY: serious, but recoverable.
_DESTRUCTIVE_CATEGORIES = frozenset({
    "root-delete", "disk", "fork-bomb", "wipe",
})


def _severity_floor(findings) -> Verdict:
    """What the findings alone would say, before any ceiling is applied."""
    alerts = [f for f in findings if f.severity is Severity.ALERT]
    if any(f.category in _DESTRUCTIVE_CATEGORIES for f in alerts):
        return Verdict.DESTRUCTIVE
    if alerts:
        return Verdict.RISKY
    warnings = [f for f in findings if f.severity is Severity.WARNING]
    if len(warnings) >= 2:
        return Verdict.RISKY
    if warnings:
        return Verdict.WORTH_A_LOOK
    notices = [f for f in findings if f.severity is Severity.NOTICE]
    if notices:
        return Verdict.WORTH_A_LOOK
    return Verdict.ROUTINE


def _ceiling(script: Script) -> tuple[Verdict, str]:
    """The floor Caveat's own blind spots put under the verdict.

    Returns the lowest verdict it is honest to give, and the reason — which the
    headline then says out loud, so a capped reading never looks like a clean
    one.
    """
    stages = list(script.walk())
    if not stages:
        return Verdict.ROUTINE, ""
    if any("$" in s.command or "`" in s.command for s in stages):
        return (Verdict.WORTH_A_LOOK,
                "the command itself is built at run time, so Caveat cannot "
                "say what runs")
    if script.quote_error:
        return (Verdict.WORTH_A_LOOK,
                "the quoting does not close, so this reading is a best guess")
    local = locally_defined(script)
    unknown = [s for s in stages
               if not is_known(s.command) and not is_function_definition(s)
               and s.command not in local]
    if unknown:
        names = ", ".join(sorted({s.command for s in unknown})[:3])
        return (Verdict.WORTH_A_LOOK,
                f"Caveat has no entry for {names}, so part of this line was "
                f"not read at all")
    return Verdict.ROUTINE, ""


def _views(script: Script, findings) -> list[StageView]:
    """One box per top-level stage, tinted by the worst thing found on it."""
    views: list[StageView] = []
    for stage in script.stages:
        views.append(StageView(stage=stage, explanation=explain_stage(stage),
                               severity=Severity.GOOD,
                               elevated=stage.elevated))
    by_index = {v.index: v for v in views}

    for finding in findings:
        for index in finding.stages:
            view = by_index.get(index)
            if view is None:
                continue
            if finding.severity.rank > view.severity.rank:
                view.severity = finding.severity
            if finding.category in ("remote-exec", "obfuscation") and (
                    runs_given_text(view.stage.command)
                    or view.stage.command == "eval"):
                view.runs_unread = True

    return views


def assess(script: Script) -> Reading:
    """Read a lexed script: findings, a verdict, and what the verdict cannot say."""
    findings = run_rules(script)
    reading = Reading(script=script, findings=findings,
                      explanations=explain(script),
                      ceiling_note=CEILING_NOTE)

    verdict = _severity_floor(findings)
    ceiling, reason = _ceiling(script)
    capped = worse(verdict, ceiling)

    reading.verdict = capped
    # The reason is said whenever the ceiling is still the binding constraint.
    # Above that, the risk itself is the bigger news and the headline says so.
    if reason and capped.rank <= ceiling.rank:
        reading.headline = f"{HEADLINES[capped]} — {reason}"
    else:
        reading.headline = HEADLINES[capped]
    reading.views = _views(script, findings)
    return reading


def read_command(source: str) -> Reading:
    """The whole pipeline in one call: split, explain, judge."""
    return assess(lex(source))
