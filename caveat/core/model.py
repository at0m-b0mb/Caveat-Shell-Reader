"""
The shapes the reading produces.

Everything Caveat learns about a command line is poured into these dataclasses,
and everything the interface draws reads from them. Nothing here splits, judges
or explains — these are the nouns, defined once, so the engine and the window
never disagree about what a "stage" or a "finding" is.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum


class Severity(Enum):
    """How much a single finding should worry the reader."""

    GOOD = "good"        # a reassuring property, not a problem
    INFO = "info"        # worth knowing, not alarming
    NOTICE = "notice"    # a soft tell
    WARNING = "warning"  # a real hazard
    ALERT = "alert"      # you should not run this on trust

    @property
    def rank(self) -> int:
        return {
            Severity.GOOD: 0,
            Severity.INFO: 1,
            Severity.NOTICE: 2,
            Severity.WARNING: 3,
            Severity.ALERT: 4,
        }[self]


class Verdict(Enum):
    """The four things Caveat is willing to say about a whole line.

    There is no letter grade here, because a command line is not a score out of
    a hundred — it either does something irreversible or it does not. The four
    words borrow the severity palette so the verdict and the findings beneath it
    are coloured by the same decision.
    """

    ROUTINE = "routine"
    WORTH_A_LOOK = "worth a look"
    RISKY = "risky"
    DESTRUCTIVE = "destructive"

    @property
    def rank(self) -> int:
        return {
            Verdict.ROUTINE: 0,
            Verdict.WORTH_A_LOOK: 1,
            Verdict.RISKY: 2,
            Verdict.DESTRUCTIVE: 3,
        }[self]

    @property
    def severity(self) -> Severity:
        """The severity voice this verdict speaks in."""
        return {
            Verdict.ROUTINE: Severity.GOOD,
            Verdict.WORTH_A_LOOK: Severity.NOTICE,
            Verdict.RISKY: Severity.WARNING,
            Verdict.DESTRUCTIVE: Severity.ALERT,
        }[self]

    @property
    def label(self) -> str:
        """The verdict as it is printed and painted."""
        return self.value.upper()


def worse(a: Verdict, b: Verdict) -> Verdict:
    """The more serious of two verdicts — how a ceiling is applied."""
    return a if a.rank >= b.rank else b


class SubKind(Enum):
    """The three ways a command line can embed another command line."""

    COMMAND = "command"    # $( ... )
    BACKTICK = "backtick"  # ` ... `
    PROCESS = "process"    # <( ... ) or >( ... )


@dataclass(frozen=True)
class Substitution:
    """One embedded command line, kept as text and read in its own right."""

    kind: SubKind
    text: str          # what sat between the delimiters
    opener: str        # the literal opener, for the explanation

    @property
    def rendered(self) -> str:
        if self.kind is SubKind.BACKTICK:
            return f"`{self.text}`"
        if self.kind is SubKind.PROCESS:
            return f"{self.opener}{self.text})"
        return f"$({self.text})"


@dataclass(frozen=True)
class Redirection:
    """One redirection operator and where it points."""

    op: str            # ">", ">>", "<", ">&", "<&", "<<", "<<<", ">|"
    fd: str            # the file descriptor written in front of it, if any
    target: str        # a path, or "&1" style descriptor, or a here-string

    @property
    def writes(self) -> bool:
        return self.op in (">", ">>", ">|", ">&")

    @property
    def truncates(self) -> bool:
        return self.op in (">", ">|")

    @property
    def rendered(self) -> str:
        return f"{self.fd}{self.op}{self.target}"


@dataclass
class Stage:
    """One command in the line — the unit the pipeline diagram draws as a box.

    A stage is what sits between two connectors: a single command with its
    arguments, its redirections, and whatever wrappers (``sudo``, ``env``,
    leading ``VAR=value`` assignments) were put in front of it.

    A stage may carry *inner* stages: the command lines Caveat found inside a
    ``$( … )`` substitution, a ``<( … )`` process substitution, or a ``-c``
    script handed to a shell. Those are read in their own right, but every
    finding about them is attributed to :attr:`root` — the top-level stage the
    reader can actually point at on the diagram.
    """

    index: int
    raw: str                                      # this stage's own text
    argv: list[str] = field(default_factory=list)  # tokens, redirections removed
    connector: str = ""                           # how it joins the stage before it
    command: str = ""                             # the resolved command word
    command_path: str = ""                        # that word exactly as written
    wrappers: list[str] = field(default_factory=list)   # sudo, env, nohup, ...
    assignments: list[str] = field(default_factory=list)  # leading VAR=value
    flags: list[str] = field(default_factory=list)
    operands: list[str] = field(default_factory=list)
    redirects: list[Redirection] = field(default_factory=list)
    substitutions: list[Substitution] = field(default_factory=list)
    elevated: bool = False                        # runs through sudo/doas/su/pkexec
    background: bool = False                      # terminated by a bare &
    quote_error: bool = False                     # the quoting did not close
    word_options: bool = False                    # -name is a word, not -n -a -m -e
    notes: list[str] = field(default_factory=list)

    inner: list["Stage"] = field(default_factory=list)   # command lines inside it
    depth: int = 0                                # 0 for a stage on the pasted line
    origin: str = ""                              # where an inner stage came from
    root: int = 0                                 # the top-level stage it belongs to

    def has_flag(self, *names: str) -> bool:
        """True if any of *names* was given, allowing for clustered shorts.

        ``-rf`` counts as both ``-r`` and ``-f``; ``--force`` is matched only
        exactly. A handful of commands spell their single-dash options as whole
        words — ``find -name``, ``find -newer`` — and the lexer marks those, so
        a word is never mistaken for a bag of letters.
        """
        for name in names:
            if name in self.flags:
                return True
            if name.startswith("--") and any(
                    token.startswith(name + "=") for token in self.flags):
                return True
            if self.word_options:
                continue
            if len(name) == 2 and name.startswith("-") and name[1].isalpha():
                letter = name[1]
                for token in self.flags:
                    if re.fullmatch(r"-[A-Za-z]{2,}", token) and letter in token[1:]:
                        return True
        return False

    def flag_value(self, *names: str) -> str:
        """The value attached to an option, whether ``--x=y`` or ``--x y``."""
        for name in names:
            for i, token in enumerate(self.flags):
                if token == name:
                    # the value is the next argv item after this flag
                    try:
                        pos = self.argv.index(token)
                    except ValueError:
                        continue
                    if pos + 1 < len(self.argv):
                        nxt = self.argv[pos + 1]
                        if not nxt.startswith("-"):
                            return nxt
                if token.startswith(name + "="):
                    return token[len(name) + 1:]
        return ""

    @property
    def is_piped_in(self) -> bool:
        """True if this stage reads the previous stage's output."""
        return self.connector in ("|", "|&")

    @property
    def text(self) -> str:
        return self.raw.strip()

    def walk(self):
        """This stage, then every stage nested inside it, depth first."""
        yield self
        for child in self.inner:
            yield from child.walk()


@dataclass
class Script:
    """A whole pasted command line, split into the stages it is made of."""

    source: str = ""
    stages: list[Stage] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def line_count(self) -> int:
        return len([ln for ln in self.source.splitlines() if ln.strip()])

    @property
    def quote_error(self) -> bool:
        return any(s.quote_error for s in self.walk())

    def walk(self):
        """Every stage at every depth, depth first."""
        for stage in self.stages:
            yield from stage.walk()

    def pipelines(self) -> list[list[Stage]]:
        """Every pipeline, at every depth — the unit the pipe rules reason over."""
        out: list[list[Stage]] = []

        def collect(siblings: list[Stage]) -> None:
            group: list[Stage] = []
            for stage in siblings:
                if stage.is_piped_in and group:
                    group.append(stage)
                else:
                    if group:
                        out.append(group)
                    group = [stage]
                collect(stage.inner)
            if group:
                out.append(group)

        collect(self.stages)
        return out

    def pipeline_of(self, index: int) -> list[Stage]:
        """Every stage joined to *index* by pipes, in order.

        ``&&``, ``||``, ``;`` and a newline start a new pipeline; only ``|``
        keeps one going, because only a pipe actually hands data along.
        """
        if not (0 <= index < len(self.stages)):
            return []
        start = index
        while start > 0 and self.stages[start].is_piped_in:
            start -= 1
        end = index
        while end + 1 < len(self.stages) and self.stages[end + 1].is_piped_in:
            end += 1
        return self.stages[start:end + 1]


@dataclass
class Explanation:
    """One stage, said out loud in plain English."""

    index: int
    command: str
    role: str                                        # "download a URL"
    kind: str = "other"                              # the family it belongs to
    known: bool = True                               # was there a dictionary entry
    flag_notes: list[tuple[str, str]] = field(default_factory=list)
    extra: list[str] = field(default_factory=list)   # subcommand / operand notes
    origin: str = ""                                 # set for a nested command line
    depth: int = 0

    @property
    def sentence(self) -> str:
        """``curl — download a URL; -s silent, -L follow redirects``"""
        head = f"{self.command} — {self.role}"
        bits = [f"{flag} {meaning}" for flag, meaning in self.flag_notes]
        bits.extend(self.extra)
        if bits:
            head += "; " + ", ".join(bits)
        return head


@dataclass
class Finding:
    """One observation, in words a person can act on."""

    severity: Severity
    title: str
    detail: str
    safer: str = ""                                  # a safer way to do it
    stages: tuple[int, ...] = ()                     # which boxes it implicates
    category: str = "general"

    @property
    def irreversible(self) -> bool:
        """True for the categories whose damage does not come back."""
        return self.category in _IRREVERSIBLE


# The categories that destroy rather than merely endanger. A line carrying one
# of these at ALERT is the only thing Caveat calls DESTRUCTIVE.
_IRREVERSIBLE = frozenset({
    "root-delete", "disk", "fork-bomb", "wipe",
})


@dataclass
class StageView:
    """Everything the pipeline diagram needs to draw one box.

    Computed in the engine rather than the widget, so the drawing code holds no
    judgement of its own and the layout can be tested without a screen.
    """

    stage: Stage
    explanation: Explanation
    severity: Severity = Severity.GOOD
    runs_unread: bool = False       # this stage executes input it never read
    elevated: bool = False

    @property
    def index(self) -> int:
        return self.stage.index

    @property
    def title(self) -> str:
        return self.stage.command or "?"


@dataclass
class Reading:
    """Everything Caveat learned about one command line."""

    script: Script = field(default_factory=Script)
    explanations: list[Explanation] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    views: list[StageView] = field(default_factory=list)
    verdict: Verdict = Verdict.ROUTINE
    headline: str = ""
    ceiling_note: str = ""

    @property
    def stages(self) -> list[Stage]:
        return self.script.stages

    @property
    def worst(self) -> Severity:
        return max((f.severity for f in self.findings), default=Severity.GOOD,
                   key=lambda s: s.rank)

    def counts(self) -> dict[str, int]:
        """How many findings in each severity, for the summary line."""
        out = {s.value: 0 for s in Severity}
        for f in self.findings:
            out[f.severity.value] += 1
        return out
