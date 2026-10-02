"""
Caveat on the command line.

The same engine the window uses, with no Qt in sight — so it runs on a server,
in a pipe, or inside another script. Point it at a file, pipe the command in,
or pass the command itself as an argument.

    caveat install.sh
    echo 'curl -fsSL https://example.com/i.sh | sudo bash' | caveat -
    caveat install.sh --json
    caveat -e 'rm -rf $DIR/'

It reads the text and prints a reading. It does not run what it is given, and
there is no flag that makes it.
"""

from __future__ import annotations

import argparse
import json
import sys

from .core.assess import read_command
from .core.explain import connector_phrase
from .core.model import Reading, Severity, Verdict

_C = {
    "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m",
    "good": "\033[32m", "notice": "\033[33m", "warning": "\033[33m",
    "alert": "\033[31m", "info": "\033[90m", "brass": "\033[33m",
}

_VERDICT_COLOUR = {
    Verdict.ROUTINE: "good",
    Verdict.WORTH_A_LOOK: "notice",
    Verdict.RISKY: "warning",
    Verdict.DESTRUCTIVE: "alert",
}


def _paint(text: str, key: str, color: bool) -> str:
    if not color:
        return text
    return f"{_C.get(key, '')}{text}{_C['reset']}"


def _wrap(text: str, width: int = 74, indent: str = "          ") -> list[str]:
    """Fold a paragraph by hand, so no third-party formatter is needed."""
    words = text.split()
    lines: list[str] = []
    current = ""
    for word in words:
        if current and len(current) + 1 + len(word) > width:
            lines.append(indent + current)
            current = word
        else:
            current = f"{current} {word}".strip()
    if current:
        lines.append(indent + current)
    return lines


def _pipeline_ascii(reading: Reading, color: bool) -> list[str]:
    """The pipeline diagram, as the terminal can draw it."""
    out: list[str] = []
    for view in reading.views:
        stage = view.stage
        if stage.index:
            phrase = connector_phrase(stage.connector)
            arrow = f"    │  {phrase}" if phrase else "    │"
            out.append(_paint(arrow, "dim", color))
        marks = []
        if view.elevated:
            marks.append("ROOT")
        if view.runs_unread:
            marks.append("RUNS UNREAD INPUT")
        if stage.background:
            marks.append("BACKGROUND")
        tail = _paint("  [" + " · ".join(marks) + "]", view.severity.value,
                      color) if marks else ""
        head = _paint(f"  {stage.index + 1}. {view.title}", "bold", color)
        out.append(f"{head}{tail}")
        out.append(_paint(f"     {view.explanation.role}", "dim", color))
    return out


def _report_text(reading: Reading, color: bool) -> str:
    out: list[str] = []
    verdict = reading.verdict
    key = _VERDICT_COLOUR[verdict]
    out.append(_paint(f"  {verdict.label}  ", "bold", color)
               + f" {reading.headline}")
    out.extend(_wrap(reading.ceiling_note, indent="  "))
    out.append("")

    if reading.views:
        out.append("The pipeline")
        out.extend(_pipeline_ascii(reading, color))
        out.append("")

    out.append("What each stage does")
    for exp in reading.explanations:
        prefix = "  " + "    " * exp.depth
        where = _paint(f"{exp.origin}  ", "dim", color) if exp.origin else ""
        out.append(f"{prefix}{where}{exp.sentence}")
    out.append("")

    counts = reading.counts()
    tally = ", ".join(f"{counts[s.value]} {s.value}" for s in Severity
                      if counts[s.value])
    out.append(f"Findings ({len(reading.findings)}" + (f": {tally}" if tally
                                                       else "") + ")")
    for finding in reading.findings:
        tag = _paint(f"[{finding.severity.value:^7}]", finding.severity.value,
                     color)
        where = ""
        if finding.stages:
            where = _paint("  stage " + ",".join(
                str(i + 1) for i in finding.stages), "dim", color)
        out.append(f"  {tag} {finding.title}{where}")
        out.extend(_paint(line, "dim", color)
                   for line in _wrap(finding.detail))
        if finding.safer:
            out.extend(_paint(line, "brass", color)
                       for line in _wrap("Instead: " + finding.safer))
        out.append("")

    for note in reading.script.notes:
        out.append(_paint(f"  note: {note}", "dim", color))
    for stage in reading.script.walk():
        for note in stage.notes:
            out.append(_paint(f"  note: stage {stage.root + 1}: {note}",
                              "dim", color))
    return "\n".join(out).rstrip() + "\n"


def _report_json(reading: Reading) -> str:
    data = {
        "verdict": {
            "name": reading.verdict.name,
            "label": reading.verdict.label,
            "rank": reading.verdict.rank,
            "headline": reading.headline,
            "ceiling_note": reading.ceiling_note,
        },
        "source": reading.script.source,
        "stages": [
            {
                "index": view.index,
                "command": view.stage.command,
                "command_path": view.stage.command_path,
                "connector": view.stage.connector,
                "connector_means": connector_phrase(view.stage.connector),
                "role": view.explanation.role,
                "sentence": view.explanation.sentence,
                "known": view.explanation.known,
                "family": view.explanation.kind,
                "elevated": view.elevated,
                "runs_unread_input": view.runs_unread,
                "background": view.stage.background,
                "severity": view.severity.value,
                "flags": view.stage.flags,
                "operands": view.stage.operands,
                "redirects": [
                    {"op": r.op, "fd": r.fd, "target": r.target,
                     "writes": r.writes}
                    for r in view.stage.redirects
                ],
                "flag_notes": [{"flag": f, "means": m}
                               for f, m in view.explanation.flag_notes],
                "nested": [
                    {"origin": child.origin, "command": child.command,
                     "raw": child.text}
                    for child in view.stage.walk() if child.depth
                ],
            }
            for view in reading.views
        ],
        "findings": [
            {"severity": f.severity.value, "title": f.title,
             "detail": f.detail, "safer": f.safer,
             "stages": list(f.stages), "category": f.category}
            for f in reading.findings
        ],
        "counts": reading.counts(),
        "notes": list(reading.script.notes) + [
            f"stage {s.root + 1}: {n}" for s in reading.script.walk()
            for n in s.notes
        ],
    }
    return json.dumps(data, indent=2)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="caveat",
        description="Explain a shell command before you run it. Caveat reads "
                    "the text and never executes it.")
    parser.add_argument("source", nargs="?", default="-",
                        help="path to a file holding the command, or - for "
                             "standard input")
    parser.add_argument("-e", "--command", metavar="TEXT", default=None,
                        help="read this text as the command instead of a file")
    parser.add_argument("--json", action="store_true",
                        help="machine-readable output")
    parser.add_argument("--no-color", action="store_true",
                        help="plain text, no ANSI")
    args = parser.parse_args(argv)

    if args.command is not None:
        raw = args.command
    elif args.source == "-":
        raw = sys.stdin.read()
    else:
        try:
            with open(args.source, encoding="utf-8", errors="replace") as fh:
                raw = fh.read()
        except OSError as exc:
            print(f"caveat: cannot read {args.source}: {exc}", file=sys.stderr)
            return 2

    if not raw.strip():
        print("caveat: no command given", file=sys.stderr)
        return 2

    reading = read_command(raw)
    if args.json:
        print(_report_json(reading))
    else:
        color = sys.stdout.isatty() and not args.no_color
        print(_report_text(reading, color), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
