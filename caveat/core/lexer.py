"""
Reading the shape of a command line.

This is a *tolerant* splitter, not a shell. It never evaluates anything: it
takes the text you pasted and works out where one command ends and the next
begins, which operator joined them, where the quotes are, what is being
redirected, and which bits of the line are really other command lines wearing a
``$( … )`` costume.

Tolerant matters more than correct here. A person pastes half a script, or a
line with one quote missing, and the tool still has to say something useful —
so every stage that cannot be tokenised cleanly says so and carries on, and the
honesty ceiling in :mod:`caveat.core.assess` notices that it did.

The work happens in two passes. :func:`chunks` walks the text once and labels
every run as a word, a quoted run, a substitution, a redirection or an operator;
after that, nothing has to think about quoting again. :func:`lex` then groups
those chunks into stages and recurses into the substitutions.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass

from .model import Redirection, Script, Stage, SubKind, Substitution

MAX_DEPTH = 3            # how far down into $( … ) Caveat will read
_MAX_STAGES = 400        # a paste this long is a script, not a command line


# --- pass one: chunks -------------------------------------------------------

@dataclass(frozen=True)
class Chunk:
    """One labelled run of the source. ``kind`` decides who looks at it."""

    kind: str          # word | quote | sub | group | redir | op | comment
    text: str          # the run exactly as it appeared
    inner: str = ""    # what sat inside the delimiters
    mark: str = ""     # the quote character, or the normalised operator
    closed: bool = True


def _take_quote(text: str, i: int) -> tuple[str, str, bool, int]:
    """Consume a quoted run starting at *i*. Returns (run, inner, closed, next)."""
    quote = text[i]
    j = i + 1
    n = len(text)
    while j < n:
        if quote == '"' and text[j] == "\\" and j + 1 < n:
            j += 2
            continue
        if text[j] == quote:
            return text[i:j + 1], text[i + 1:j], True, j + 1
        j += 1
    return text[i:], text[i + 1:], False, n


def _take_paren(text: str, i: int, open_len: int) -> tuple[str, str, bool, int]:
    """Consume ``$( … )``, ``<( … )``, ``( … )`` with nesting and quotes."""
    j = i + open_len
    n = len(text)
    depth = 1
    while j < n:
        ch = text[j]
        if ch == "\\" and j + 1 < n:
            j += 2
            continue
        if ch in "'\"":
            _, _, _, j = _take_quote(text, j)
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[i:j + 1], text[i + open_len:j], True, j + 1
        j += 1
    return text[i:], text[i + open_len:], False, n


def _take_brace(text: str, i: int) -> tuple[str, str, bool, int]:
    """Consume ``${ … }``."""
    j = i + 2
    n = len(text)
    depth = 1
    while j < n:
        ch = text[j]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[i:j + 1], text[i + 2:j], True, j + 1
        j += 1
    return text[i:], text[i + 2:], False, n


def _take_redirect(text: str, i: int) -> tuple[str, int]:
    """Consume a redirection operator whole, so ``2>&1`` keeps its ampersand."""
    n = len(text)
    j = i
    while j < n and text[j] in "<>":
        j += 1
    if j < n and text[j] == "|" and text[i:j] == ">":
        j += 1
    elif text[i:j] == "<<" and j < n and text[j] == "-":
        j += 1
    if j < n and text[j] == "&":
        j += 1
        while j < n and (text[j].isdigit() or text[j] == "-"):
            j += 1
    return text[i:j], j


_TRAILING_FD = re.compile(r"(?<!\S)(\d+)$")


def chunks(text: str) -> list[Chunk]:
    """Label every run of *text* once, so later passes ignore quoting."""
    out: list[Chunk] = []
    word: list[str] = []
    i, n = 0, len(text)

    def flush() -> None:
        if word:
            out.append(Chunk("word", "".join(word)))
            word.clear()

    def at_word_start() -> bool:
        """True where a ``#`` would open a comment rather than be a character."""
        tail = "".join(word)
        if tail and not tail[-1].isspace():
            return False
        return not (out and out[-1].kind in ("word", "quote", "sub", "group")
                    and not tail)

    while i < n:
        ch = text[i]

        if ch == "\\":
            if i + 1 < n:
                word.append(text[i:i + 2])
                i += 2
            else:
                word.append(ch)
                i += 1
            continue

        if ch == "#" and at_word_start():
            end = text.find("\n", i)
            end = n if end == -1 else end
            flush()
            out.append(Chunk("comment", text[i:end]))
            i = end
            continue

        if ch in "'\"":
            flush()
            run, inner, closed, i = _take_quote(text, i)
            out.append(Chunk("quote", run, inner=inner, mark=ch, closed=closed))
            continue

        if ch == "`":
            flush()
            end = text.find("`", i + 1)
            if end == -1:
                out.append(Chunk("sub", text[i:], inner=text[i + 1:],
                                 mark="`", closed=False))
                i = n
            else:
                out.append(Chunk("sub", text[i:end + 1], inner=text[i + 1:end],
                                 mark="`"))
                i = end + 1
            continue

        if text[i:i + 2] == "$(":
            flush()
            run, inner, closed, i = _take_paren(text, i, 2)
            out.append(Chunk("sub", run, inner=inner, mark="$(", closed=closed))
            continue

        if text[i:i + 2] == "${":
            flush()
            run, inner, closed, i = _take_brace(text, i)
            out.append(Chunk("group", run, inner=inner, mark="${", closed=closed))
            continue

        if ch in "<>" and text[i + 1:i + 2] == "(":
            flush()
            run, inner, closed, i = _take_paren(text, i, 2)
            out.append(Chunk("sub", run, inner=inner, mark=ch + "(", closed=closed))
            continue

        # A bare ``( … )`` subshell is deliberately *not* opaque: the commands
        # inside it are real stages the reader should see, so the parentheses
        # are carried along as ordinary characters and dropped from argv later.

        if ch == "&" and text[i + 1:i + 2] == ">":
            flush()
            run, i = _take_redirect(text, i + 1)
            out.append(Chunk("redir", "&" + run))
            continue

        if ch in "<>":
            # a file descriptor written tight against the operator belongs to it
            fd = ""
            tail = "".join(word)
            match = _TRAILING_FD.search(tail)
            if match:
                fd = match.group(1)
                word.clear()
                if tail[:match.start()]:
                    word.append(tail[:match.start()])
            flush()
            run, i = _take_redirect(text, i)
            out.append(Chunk("redir", fd + run, mark=fd))
            continue

        two = text[i:i + 2]
        if two in ("&&", "||", "|&"):
            flush()
            out.append(Chunk("op", two, mark=two))
            i += 2
            continue
        if two == ";;":
            flush()
            out.append(Chunk("op", two, mark=";"))
            i += 2
            continue
        if ch in "|;&\n":
            flush()
            out.append(Chunk("op", ch, mark=ch))
            i += 1
            continue

        word.append(ch)
        i += 1

    flush()
    return out


# --- here-documents ---------------------------------------------------------

_HEREDOC = re.compile(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")


def strip_heredocs(source: str) -> tuple[str, list[str]]:
    """Set aside here-document bodies so they are not read as commands.

    A here-document is data, not a command line, and feeding its text through
    the splitter would invent stages that do not exist. Caveat says plainly that
    it put the body aside rather than pretending to have read it.
    """
    lines = source.splitlines(keepends=True)
    out: list[str] = []
    notes: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        out.append(line)
        delims = [m.group(2) for m in _HEREDOC.finditer(line)]
        i += 1
        for delim in delims:
            body = 0
            while i < len(lines) and lines[i].strip() != delim:
                body += 1
                i += 1
            if i < len(lines):
                i += 1  # the terminator line itself
            notes.append(
                f"A here-document ({delim}) of {body} line"
                f"{'' if body == 1 else 's'} was set aside: Caveat reads the "
                f"command, not the text fed into it.")
    return "".join(out), notes


# --- tokenising a single stage ----------------------------------------------

def tokenise(text: str) -> tuple[list[str], bool, list[str]]:
    """Split one stage into argv. Returns (argv, had_trouble, notes)."""
    notes: list[str] = []
    try:
        return shlex.split(text, posix=True), False, notes
    except ValueError:
        pass
    for closer in ('"', "'"):
        try:
            argv = shlex.split(text + closer, posix=True)
        except ValueError:
            continue
        notes.append(
            "The quoting in this stage never closed. Caveat read it as though "
            "the missing quote sat at the end of the line — your shell may "
            "split it somewhere else entirely.")
        return argv, True, notes
    notes.append(
        "Caveat could not tokenise this stage, so it fell back to splitting on "
        "spaces. Treat the words below as a guess.")
    return [t.strip("'\"") for t in text.split()], True, notes


_REDIR_TOKEN = re.compile(r"^(\d*)(&>>|&>|>>|>\||>&|<&|<<<|<<-|<<|>|<)(.*)$")


def parse_redirection(token: str, target: str = "") -> Redirection | None:
    """Read one redirection token, with *target* for ``> file`` written apart."""
    match = _REDIR_TOKEN.match(token)
    if not match:
        return None
    fd, op, rest = match.groups()
    if op in (">&", "<&") and rest:
        return Redirection(op=op, fd=fd, target=rest)
    return Redirection(op=op, fd=fd, target=rest or target)


# --- command resolution -----------------------------------------------------

ELEVATORS = frozenset({"sudo", "doas", "pkexec", "su", "sudoedit", "runas"})

# The commands whose ``-c`` argument really is another shell command line. A
# ``-c`` belonging to anything else (``curl -c cookies.txt``) is left alone,
# because reading a cookie jar as a script would invent findings.
SHELL_RUNNERS = frozenset({
    "sh", "bash", "zsh", "dash", "ksh", "csh", "tcsh", "fish", "ash",
    "busybox", "su", "sudo", "doas", "pkexec",
})

# Commands that spell their single-dash options as whole words, so ``-name`` is
# one option rather than four clustered letters. Everything else is assumed to
# cluster, which is the overwhelmingly common convention.
WORD_OPTION_COMMANDS = frozenset({
    "find", "java", "openssl", "ffmpeg", "convert", "mogrify", "mkfs",
})

# Shell punctuation that shlex hands back as a token but which is not an
# argument to anything.
_PUNCTUATION = frozenset({"(", ")", "{", "}", "!", "[[", "]]"})

# Wrappers that run another command without changing who you are. Reading
# through them is what lets a rule see ``bash`` in ``sudo -E nohup bash``.
WRAPPERS = frozenset({
    "env", "nohup", "nice", "ionice", "time", "command", "exec", "builtin",
    "stdbuf", "setsid", "unbuffer", "script",
}) | ELEVATORS

_SUDO_VALUE = frozenset({
    "-u", "-g", "-p", "-C", "-U", "-h", "-r", "-t", "-c", "--user", "--group",
    "--prompt", "--close-from", "--other-user", "--host", "--role", "--type",
    "--command",
})
_WRAPPER_VALUE = frozenset({"-u", "-n", "-o", "-i"})
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


@dataclass
class Resolved:
    wrappers: list[str]
    assignments: list[str]
    command: str
    command_path: str
    rest: list[str]
    elevated: bool


def resolve_command(argv: list[str]) -> Resolved:
    """Read past assignments and wrappers to the command that really runs."""
    wrappers: list[str] = []
    assignments: list[str] = []
    elevated = False
    i = 0
    n = len(argv)

    while i < n:
        token = argv[i]
        if token in _PUNCTUATION:
            i += 1
            continue
        if _ASSIGNMENT.match(token):
            assignments.append(token)
            i += 1
            continue
        name = token.rsplit("/", 1)[-1]
        if name not in WRAPPERS:
            break
        wrappers.append(name)
        if name in ELEVATORS:
            elevated = True
        i += 1
        # step over the wrapper's own options (and their values)
        values = _SUDO_VALUE if name in ELEVATORS else _WRAPPER_VALUE
        while i < n:
            opt = argv[i]
            if _ASSIGNMENT.match(opt) and name in ("env", "sudo"):
                assignments.append(opt)
                i += 1
                continue
            if not opt.startswith("-") or opt == "-":
                break
            if opt == "--":
                i += 1
                break
            if opt in values and i + 1 < n:
                if name in ELEVATORS and opt == "-c":
                    # `su -c "…"` keeps the shell as the command; the script
                    # itself is picked up as nested text later.
                    break
                i += 2
                continue
            i += 1
        # `sudo` with nothing after it is a request for a root shell
        if i >= n:
            break
        if name == "su" and argv[i:i + 1] and not argv[i].startswith("-"):
            # `su someuser` — the operand is a user, not a command
            if i + 1 >= n:
                i = n
                break

    rest = [t for t in argv[i:] if t not in _PUNCTUATION]
    command_path = rest[0] if rest else ""
    command = command_path.rsplit("/", 1)[-1] if rest else ""
    if rest:
        rest = rest[1:]
    if command in ("", "-", "--"):
        # `sudo -i`, `su -` and friends: the elevator itself is the command.
        command = wrappers[-1] if wrappers else command
        command_path = command
    return Resolved(wrappers=wrappers, assignments=assignments,
                    command=command, command_path=command_path, rest=rest,
                    elevated=elevated)


def split_flags(rest: list[str]) -> tuple[list[str], list[str]]:
    """Separate option-looking tokens from operands, stopping at ``--``."""
    flags: list[str] = []
    operands: list[str] = []
    after_ddash = False
    for token in rest:
        if token in _PUNCTUATION:
            continue
        if after_ddash:
            operands.append(token)
            continue
        if token == "--":
            after_ddash = True
            continue
        if token.startswith("-") and token != "-" and len(token) > 1:
            flags.append(token)
        else:
            operands.append(token)
    return flags, operands


# --- pass two: stages -------------------------------------------------------

def collect_substitutions(parts: list[Chunk]) -> list[Substitution]:
    """Every embedded command line, including those inside double quotes.

    Single quotes are skipped on purpose: a shell does not expand inside them,
    so neither does Caveat.
    """
    found: list[Substitution] = []
    for chunk in parts:
        if chunk.kind == "sub":
            kind = (SubKind.BACKTICK if chunk.mark == "`"
                    else SubKind.PROCESS if chunk.mark in ("<(", ">(")
                    else SubKind.COMMAND)
            found.append(Substitution(kind=kind, text=chunk.inner,
                                      opener=chunk.mark))
            found.extend(collect_substitutions(chunks(chunk.inner)))
        elif chunk.kind == "quote" and chunk.mark == '"':
            found.extend(collect_substitutions(chunks(chunk.inner)))
        elif chunk.kind == "group":
            found.extend(collect_substitutions(chunks(chunk.inner)))
    return found


def unquoted_text(text: str) -> str:
    """Only the parts of *text* a shell would expand without protection.

    Quoted runs, substitutions and comments are dropped, which is what lets the
    unquoted-variable rule tell ``rm -rf $DIR`` from ``rm -rf "$DIR"`` and leave
    ``awk '{print $2}'`` alone.
    """
    return " ".join(c.text for c in chunks(text) if c.kind == "word")


def _single_quoted(text: str) -> str:
    """Wrap *text* so :func:`shlex.split` hands it back as exactly one token."""
    return "'" + text.replace("'", "'\\''") + "'"


def _clean_and_redirects(parts: list[Chunk]) -> tuple[str, list[Redirection]]:
    """Rebuild a stage's text without its redirections, and list them.

    Substitutions are re-quoted on the way through. Left alone, ``shlex`` would
    split ``<(curl -s http://x)`` into three words and credit ``-s`` to the
    *outer* command, which is how a tool ends up explaining flags that were
    never there.
    """
    pieces: list[str] = []
    redirects: list[Redirection] = []
    i = 0
    while i < len(parts):
        chunk = parts[i]
        if chunk.kind == "comment":
            i += 1
            continue
        if chunk.kind == "sub":
            pieces.append(_single_quoted(chunk.text))
            i += 1
            continue
        if chunk.kind != "redir":
            pieces.append(chunk.text)
            i += 1
            continue

        token = chunk.text
        target = ""
        consumed = 1
        if not _REDIR_TOKEN.match(token):
            i += 1
            continue
        _, op, rest = _REDIR_TOKEN.match(token).groups()
        if not rest:
            nxt = parts[i + 1] if i + 1 < len(parts) else None
            if nxt is not None and nxt.kind in ("word", "quote", "sub", "group"):
                if nxt.kind == "word":
                    stripped = nxt.text.lstrip()
                    lead = nxt.text[:len(nxt.text) - len(stripped)]
                    first, _, tail = stripped.partition(" ")
                    target = first
                    remainder = lead + tail if tail else ""
                    if remainder.strip():
                        parts[i + 1] = Chunk("word", remainder)
                        consumed = 1
                    else:
                        consumed = 2
                else:
                    target = nxt.inner or nxt.text
                    consumed = 2
        red = parse_redirection(token, target)
        if red is not None:
            redirects.append(red)
        i += consumed
    return "".join(pieces), redirects


_NESTING_FLAGS = ("-c", "--command")


def _nested_sources(stage: Stage, argv: list[str]) -> list[tuple[str, str]]:
    """The command lines this stage would run, as (origin, text) pairs."""
    out: list[tuple[str, str]] = []
    seen: set[str] = set()

    def offer(origin: str, text: str) -> None:
        """Take a nested command line, unless it is only a substitution.

        ``sh -c "$(curl …)"`` would otherwise be read twice: once as the
        substitution, and once as a ``-c`` script whose entire text *is* that
        substitution. Reading ``$(curl …)`` as a command would invent a command
        called ``$(curl``, so a payload that is nothing but substitutions is
        dropped here and read through :attr:`Stage.substitutions` instead.
        """
        reduced = text
        for sub in stage.substitutions:
            reduced = reduced.replace(sub.rendered, " ")
        key = text.strip()
        if not reduced.strip() or not key or key in seen:
            return
        seen.add(key)
        out.append((origin, text))

    for sub in stage.substitutions:
        if sub.text.strip():
            key = sub.text.strip()
            if key not in seen:
                seen.add(key)
                out.append((f"inside {sub.rendered}", sub.text))

    if stage.command in SHELL_RUNNERS:
        for i, token in enumerate(argv):
            if token in _NESTING_FLAGS and i + 1 < len(argv):
                offer(f"inside the {token} script", argv[i + 1])
            elif any(token.startswith(f + "=") for f in _NESTING_FLAGS):
                offer(f"inside the {token.split('=')[0]} script",
                      token.split("=", 1)[1])

    if stage.command == "eval":
        for operand in stage.operands:
            offer("inside the eval string", operand)

    return out


def _group_chunks(parts: list[Chunk]) -> list[tuple[str, list[Chunk], bool]]:
    """Cut a chunk list at every top-level operator."""
    groups: list[tuple[str, list[Chunk], bool]] = []
    current: list[Chunk] = []
    connector = ""

    def flush(next_connector: str, background: bool) -> None:
        nonlocal current, connector
        if any(c.text.strip() for c in current if c.kind != "comment"):
            groups.append((connector, current, background))
        current = []
        connector = next_connector

    for chunk in parts:
        if chunk.kind != "op":
            current.append(chunk)
            continue
        op = chunk.mark
        if op == "&":
            flush(";", True)
        else:
            flush(op, False)
    flush("", False)
    return groups


def _build_stage(index: int, connector: str, parts: list[Chunk],
                 background: bool, depth: int, root: int,
                 origin: str) -> Stage:
    raw = "".join(c.text for c in parts)
    clean, redirects = _clean_and_redirects(list(parts))
    argv, trouble, notes = tokenise(clean)
    unclosed = [c for c in parts if not c.closed]

    stage = Stage(index=index, raw=raw, argv=argv, connector=connector,
                  redirects=redirects, background=background,
                  quote_error=trouble or bool(unclosed), notes=list(notes),
                  depth=depth, origin=origin, root=root)
    stage.substitutions = collect_substitutions(parts)

    resolved = resolve_command(argv)
    stage.wrappers = resolved.wrappers
    stage.assignments = resolved.assignments
    stage.command = resolved.command
    stage.command_path = resolved.command_path
    stage.elevated = resolved.elevated
    stage.word_options = stage.command in WORD_OPTION_COMMANDS
    stage.flags, stage.operands = split_flags(resolved.rest)

    if unclosed and not trouble:
        stage.notes.append(
            "A quote or bracket in this stage was never closed; Caveat read to "
            "the end of the text.")
    if stage.background:
        stage.notes.append(
            "This stage ends in '&', so it keeps running after the line returns.")

    if depth < MAX_DEPTH:
        for sub_origin, text in _nested_sources(stage, argv):
            for child in _stages(text, depth + 1, root, sub_origin):
                stage.inner.append(child)
    elif stage.substitutions:
        stage.notes.append(
            "Caveat stopped reading further into the nested commands here.")
    return stage


def _stages(text: str, depth: int, root: int, origin: str) -> list[Stage]:
    out: list[Stage] = []
    for index, (connector, parts, background) in enumerate(
            _group_chunks(chunks(text))):
        if len(out) >= _MAX_STAGES:
            break
        stage = _build_stage(len(out), connector if index else "", parts,
                             background, depth,
                             root if depth else len(out), origin)
        if not stage.command and not stage.redirects:
            # punctuation left over from a brace group or a stray terminator
            continue
        out.append(stage)
    return out


def lex(source: str) -> Script:
    """Read a pasted command line into a :class:`Script`."""
    body, notes = strip_heredocs(source)
    script = Script(source=source, notes=list(notes))
    script.stages = _stages(body, 0, 0, "")
    for index, stage in enumerate(script.stages):
        stage.index = index
        for child in stage.walk():
            child.root = index
    if script.stages:
        script.stages[0].connector = ""
    if len(script.stages) >= _MAX_STAGES:
        script.notes.append(
            f"Caveat read the first {_MAX_STAGES} stages and stopped; this is a "
            f"script, not a command line.")
    return script
