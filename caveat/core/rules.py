"""
The risk detections — what is worth saying, and what to do instead.

Each rule looks at a *property of the command you pasted* and, when it fires,
says three things: what it found, why that matters in one short paragraph, and a
safer way to get the same job done. The third part is the one that earns the
tool its place; a warning with no alternative only teaches people to click past
warnings.

Two rules about the rules:

* **Shapes, not names.** A detection asks "is a *fetcher* piped into something
  that *executes what it is given*", never "is this one of these twelve bad
  domains". A blocklist is always out of date and it teaches nothing; the shape
  ``download | shell`` is as true next year as it is today, and once you can see
  it you can see it anywhere.
* **No rule ever says a line is safe.** A rule can only say what it found. The
  absence of findings is reported as an absence, in :mod:`caveat.core.assess`,
  and never as a clearance.

The few GOOD findings at the end of this module are the exception that proves
it: each one states a narrow, checkable property — "the download lands in a
file", "nothing here asks for root" — and none of them adds up to approval.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable

from .explain import (
    DECODERS,
    FETCH,
    READ_ONLY_COMMANDS,
    is_known,
    kind_of,
    runs_given_text,
)
from .lexer import unquoted_text
from .model import Finding, Script, Severity, Stage

# --- shared vocabulary ------------------------------------------------------

ROOTISH = frozenset({"/", "/*", "/.", "//", "/./", "/*/"})
HOMEISH = frozenset({
    "~", "~/", "~/*", "$HOME", "${HOME}", "$HOME/", "$HOME/*", "${HOME}/",
    "${HOME}/*", "/root", "/root/", "/root/*",
})
SYSTEM_DIRS = frozenset({
    "/usr", "/etc", "/var", "/bin", "/sbin", "/lib", "/lib64", "/opt", "/boot",
    "/home", "/Users", "/System", "/Library", "/Applications", "/private",
    "/proc", "/sys", "/srv", "/run",
})
SYSTEM_WRITE_PREFIXES = (
    "/etc/", "/usr/", "/bin/", "/sbin/", "/boot/", "/lib/", "/System/",
    "/Library/", "/var/lib/", "/var/spool/cron",
)
HOME_PREFIXES = ("/home/", "/Users/", "~", "$HOME", "./", "/tmp/", "/var/tmp/")

BLOCK_DEVICE = re.compile(
    r"^/dev/(sd[a-z]|nvme\d|disk\d|rdisk\d|hd[a-z]|vd[a-z]|mmcblk\d|loop\d|"
    r"xvd[a-z]|md\d|dm-\d)")
URL = re.compile(r"[a-zA-Z][a-zA-Z0-9+.-]*://[^\s'\"<>|;)]+")
VARIABLE = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*|[0-9]|[@*])\}?")
BARE_VAR_PATH = re.compile(r"^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?(/\*?|/.*)$")
BARE_VAR = re.compile(r"^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$")
LONG_BLOB = re.compile(r"^[A-Za-z0-9+/=_-]{120,}$")
FORK_BOMB = re.compile(
    r"([A-Za-z_:][\w:.]{0,7})\s*\(\s*\)\s*\{\s*\1\s*\|\s*\1\s*&\s*;?\s*\}")
FUNCTION_DEF = re.compile(r"^[^\s()]*\(\)?\{?$|^[^\s()]*\(\)")
FUNCTION_NAME = re.compile(
    r"(?:^|[\n;&|{(]|\bfunction\s+)\s*([A-Za-z_:][\w:.]*)\s*\(\s*\)", re.M)

# Shell variables that never hold a path, so the quoting rule leaves them be.
_STATUS_VARS = frozenset({"$?", "$$", "$!", "$#", "$0", "$-", "$_"})

LOG_PATHS = (
    "/var/log", ".bash_history", ".zsh_history", ".sh_history",
    ".python_history", "/wtmp", "/utmp", "/btmp", "/lastlog", "auth.log",
    "secure.log", "/var/audit",
)

Rule = Callable[[Script], list[Finding]]


# --- helpers ----------------------------------------------------------------

def _words(stage: Stage) -> list[str]:
    """Everything in a stage that could name a thing: operands and targets."""
    return list(stage.operands) + [r.target for r in stage.redirects if r.target]


def _tokens(stage: Stage) -> list[str]:
    return list(stage.flags) + _words(stage) + list(stage.assignments)


def _urls(stage: Stage) -> list[str]:
    return URL.findall(stage.raw)


def _where(stage: Stage) -> str:
    """How a finding refers to a stage the reader can point at."""
    name = stage.command or "this stage"
    if stage.depth:
        return f"`{name}` {stage.origin}"
    return f"stage {stage.index + 1} (`{name}`)"


def _strip_path(target: str) -> str:
    """Normalise a delete target so ``/usr/`` and ``/usr/*`` read alike.

    A target that is *only* a glob is returned unchanged: stripping it would
    leave an empty string, and reading an empty string as ``/`` would report a
    bare ``rm -rf *`` as an attack on the filesystem root.
    """
    cleaned = target.rstrip("*")
    if len(cleaned) > 1:
        cleaned = cleaned.rstrip("/")
    return cleaned if cleaned else target


def is_function_definition(stage: Stage) -> bool:
    """True where the 'command' is really the head of a function definition.

    ``name() { … }`` makes the first word look like a command nobody has heard
    of. Saying "no entry for `name(){`" would be true and useless, so this is
    reported as what it is instead.
    """
    return bool(stage.command) and bool(FUNCTION_DEF.match(stage.command))


def locally_defined(script: Script) -> frozenset[str]:
    """The names this very text defines as shell functions.

    A call to one of them is not an unknown command — the body is right there,
    and Caveat has already read it as stages. Treating it as unknown would cap
    a line that was in fact read in full.
    """
    return frozenset(FUNCTION_NAME.findall(script.source))


def _decodes(stage: Stage) -> bool:
    """True for a stage whose job is turning one representation into another."""
    if stage.command not in DECODERS:
        return False
    if stage.command in ("base64",):
        return stage.has_flag("-d", "--decode", "-D")
    if stage.command == "xxd":
        return stage.has_flag("-r")
    if stage.command == "openssl":
        return "enc" in stage.operands and stage.has_flag("-d")
    if stage.command == "gzip":
        return stage.has_flag("-d")
    return True  # gunzip, bunzip2, uudecode, tr, rev reshape by definition


def _runners(stages: Iterable[Stage]) -> list[Stage]:
    return [s for s in stages if runs_given_text(s.command)]


def _is_read_only(stage: Stage) -> bool:
    if stage.command not in READ_ONLY_COMMANDS:
        return False
    if any(r.writes for r in stage.redirects):
        return False
    if stage.command == "find" and stage.has_flag("-delete"):
        return False
    return True


# --- running code you have not read ----------------------------------------

def rule_download_into_shell(script: Script) -> list[Finding]:
    """``curl … | sh`` and every variation of it."""
    out: list[Finding] = []
    for pipeline in script.pipelines():
        positions = {id(s): i for i, s in enumerate(pipeline)}
        fetchers = [s for s in pipeline if kind_of(s.command) == FETCH]
        runners = _runners(pipeline)
        for fetcher in fetchers:
            after = [r for r in runners
                     if positions[id(r)] > positions[id(fetcher)]]
            if not after:
                continue
            runner = after[0]
            url = (_urls(fetcher) or ["the URL"])[0]
            root = "as root, " if runner.elevated or fetcher.elevated else ""
            out.append(Finding(
                Severity.ALERT,
                "Downloaded code is piped straight into a shell",
                f"{fetcher.command} fetches {url} and `{runner.command}` runs "
                f"it {root}line by line as it arrives. You are running code you "
                f"have not read — and nobody can read it, because the server "
                f"decides what to send at the moment you ask, and can send you "
                f"something different from what it sends everyone else.",
                safer=f"Split it in two. Fetch to a file, read the file, then "
                      f"run it: `{fetcher.command} -o setup.sh {url}` then "
                      f"`less setup.sh` then `sh setup.sh`.",
                stages=(fetcher.root, runner.root), category="remote-exec"))
    return out


def rule_runs_substituted_download(script: Script) -> list[Finding]:
    """``bash <(curl …)``, ``eval "$(curl …)"``, ``sh -c "$(curl …)"``."""
    out: list[Finding] = []
    for stage in script.walk():
        if not (runs_given_text(stage.command) or stage.command == "eval"):
            continue
        nested = [c for child in stage.inner for c in child.walk()]
        fetchers = [c for c in nested if kind_of(c.command) == FETCH]
        if not fetchers:
            continue
        fetcher = fetchers[0]
        url = (_urls(fetcher) or ["a URL"])[0]
        out.append(Finding(
            Severity.ALERT,
            "A download is substituted in and then run",
            f"`{stage.command}` is handed the *output* of {fetcher.command} "
            f"{url} and executes it. The brackets hide the same bargain as a "
            f"pipe into a shell: the text is fetched and run in one breath, "
            f"with no moment in between where anyone reads it.",
            safer="Fetch to a file, read it, then run the file.",
            stages=(stage.root,), category="remote-exec"))
    return out


def rule_decoded_into_shell(script: Script) -> list[Finding]:
    """Something is unpacked from an encoding and then executed."""
    out: list[Finding] = []
    for pipeline in script.pipelines():
        positions = {id(s): i for i, s in enumerate(pipeline)}
        decoders = [s for s in pipeline if _decodes(s)]
        runners = _runners(pipeline)
        for decoder in decoders:
            after = [r for r in runners
                     if positions[id(r)] > positions[id(decoder)]]
            if not after:
                continue
            runner = after[0]
            out.append(Finding(
                Severity.ALERT,
                "Encoded text is decoded and then run as code",
                f"`{decoder.command}` turns the text back into its original "
                f"bytes and `{runner.command}` executes the result. Encoding is "
                f"not encryption and it is not compression for its own sake "
                f"here — it is there so that you cannot see what you are about "
                f"to run by looking at the line.",
                safer=f"Decode it into a file and read it first: pipe the "
                      f"`{decoder.command}` output to `cat` or into a file "
                      f"instead of into `{runner.command}`.",
                stages=(decoder.root, runner.root), category="obfuscation"))
    return out


def rule_long_encoded_blob(script: Script) -> list[Finding]:
    """A wall of encoded characters, which is its own kind of tell."""
    out: list[Finding] = []
    for stage in script.walk():
        for token in _tokens(stage) + stage.argv:
            if LONG_BLOB.match(token):
                out.append(Finding(
                    Severity.NOTICE,
                    "A long run of encoded text is embedded in the line",
                    f"{_where(stage).capitalize()} carries {len(token)} "
                    f"characters of encoded text. Caveat does not decode it, "
                    f"and that is the point: whatever it says, neither you nor "
                    f"the person who sent it to you is reading it here.",
                    safer="Decode it on its own, into a file, and read it "
                          "before any part of this line runs.",
                    stages=(stage.root,), category="obfuscation"))
                return out
    return out


def rule_eval(script: Script) -> list[Finding]:
    """``eval`` turns data back into code, which is the whole hazard."""
    out: list[Finding] = []
    for stage in script.walk():
        if stage.command != "eval":
            continue
        out.append(Finding(
            Severity.WARNING,
            "eval turns text back into commands",
            f"{_where(stage).capitalize()} hands a string to `eval`, which "
            f"parses it as shell source and runs it. Whatever produced that "
            f"string — a variable, a file, a server — decides what runs.",
            safer="Call the command directly instead of building it as text. "
                  "If the value really must come from elsewhere, print it and "
                  "read it before you run it.",
            stages=(stage.root,), category="eval"))
    return out


# --- destroying things ------------------------------------------------------

def rule_recursive_delete(script: Script) -> list[Finding]:
    """``rm -rf`` and the handful of targets that make it unrecoverable."""
    out: list[Finding] = []
    for stage in script.walk():
        if stage.command not in ("rm", "srm"):
            continue
        recursive = stage.has_flag("-r", "-R", "--recursive")
        force = stage.has_flag("-f", "--force")
        no_preserve = "--no-preserve-root" in stage.flags
        targets = [t for t in stage.operands]
        flagged = False

        if no_preserve:
            out.append(Finding(
                Severity.ALERT,
                "This asks to delete the filesystem root itself",
                "`--no-preserve-root` exists for exactly one reason: `rm` "
                "refuses to delete `/` without it. Its presence is not an "
                "accident — somebody wrote this line to get past that refusal.",
                safer="There is no safer form of this. Delete the one directory "
                      "you actually mean, by name.",
                stages=(stage.root,), category="root-delete"))
            flagged = True

        for target in targets:
            norm = _strip_path(target)
            if target in ROOTISH or norm == "/":
                out.append(Finding(
                    Severity.ALERT,
                    "The delete target is the whole filesystem",
                    f"{_where(stage).capitalize()} points `rm` at `{target}` — "
                    f"every file on the machine, including the system that "
                    f"would let you put it back. A single stray space before a "
                    f"`/` is enough to turn a sensible line into this one.",
                    safer="Name the directory you mean, and run it without `-f` "
                          "first so you are told what would go.",
                    stages=(stage.root,), category="root-delete"))
                flagged = True
            elif target in HOMEISH or norm in HOMEISH:
                out.append(Finding(
                    Severity.ALERT,
                    "The delete target is your whole home directory",
                    f"`{target}` is everything you own: documents, keys, "
                    f"configuration, the lot. The system would survive this; "
                    f"your work would not.",
                    safer="Name the subdirectory you mean.",
                    stages=(stage.root,), category="wipe"))
                flagged = True
            elif norm in SYSTEM_DIRS:
                out.append(Finding(
                    Severity.ALERT,
                    f"The delete target is a system directory ({norm})",
                    f"`{target}` holds part of the operating system. Removing "
                    f"it recursively leaves a machine that may not boot and "
                    f"cannot be repaired from inside itself.",
                    safer="Name the one thing you mean to remove, inside that "
                          "directory.",
                    stages=(stage.root,), category="wipe"))
                flagged = True
            elif BARE_VAR_PATH.match(target):
                out.append(Finding(
                    Severity.ALERT,
                    "The delete target is a variable with a path glued on",
                    f"`{target}` is built from a variable. If that variable is "
                    f"empty or unset — a typo in its name is enough — the path "
                    f"your shell builds is `{target.split('}')[-1] or '/'}` "
                    f"and the delete starts at the root. This is the single "
                    f"most common way a working script destroys a machine.",
                    safer="Check it first: `[ -n \"$VAR\" ] || exit 1`, and "
                          "quote it as `\"$VAR\"/thing`.",
                    stages=(stage.root,), category="root-delete"))
                flagged = True
            elif BARE_VAR.match(target):
                out.append(Finding(
                    Severity.WARNING,
                    "The delete target comes from a variable",
                    f"Caveat cannot know what `{target}` holds when this runs, "
                    f"so it cannot tell you what would be deleted. Neither can "
                    f"you, by reading this line.",
                    safer="Print it before you delete with it: `echo "
                          f"\"{target}\"`.",
                    stages=(stage.root,), category="destroy"))
                flagged = True
            elif target in ("*", "./*", ".", "..", "./") and recursive:
                out.append(Finding(
                    Severity.WARNING,
                    f"The delete target is everything here (`{target}`)",
                    "This removes the whole current directory tree, and which "
                    "directory that is depends on where you happen to be "
                    "standing when you run it.",
                    safer="Use an absolute path, so the line means the same "
                          "thing wherever it is run from.",
                    stages=(stage.root,), category="destroy"))
                flagged = True

        if recursive and not flagged:
            named = ", ".join(f"`{t}`" for t in targets[:3]) or "its arguments"
            out.append(Finding(
                Severity.NOTICE,
                "A recursive delete, with nothing to stop it",
                f"{_where(stage).capitalize()} deletes {named} and everything "
                f"underneath."
                + (" `-f` also means you will not be warned about anything "
                   "that is missing, so a mistyped path fails silently."
                   if force else ""),
                safer="Run it as `ls -R` on the same path first, or drop `-f` "
                      "so `rm` tells you what it cannot find.",
                stages=(stage.root,), category="destroy"))
    return out


def rule_disk_destruction(script: Script) -> list[Finding]:
    """Writes that go past the filesystem and straight at a device."""
    out: list[Finding] = []
    for stage in script.walk():
        kind = kind_of(stage.command)

        if stage.command == "dd":
            dest = next((o.split("=", 1)[1] for o in stage.operands
                         if o.startswith("of=")), "")
            if dest and BLOCK_DEVICE.match(dest):
                out.append(Finding(
                    Severity.ALERT,
                    f"This writes raw bytes over the device {dest}",
                    f"`dd of={dest}` does not write a file — it writes over the "
                    f"disk itself, past every filesystem, partition table and "
                    f"permission check. There is no undo and no recycle bin, "
                    f"and a wrong letter in the device name picks a different "
                    f"disk.",
                    safer="Confirm the device first with `diskutil list` or "
                          "`lsblk`, and write to an image file rather than a "
                          "device unless you are certain.",
                    stages=(stage.root,), category="disk"))
            elif dest:
                out.append(Finding(
                    Severity.WARNING,
                    f"This overwrites {dest} byte for byte",
                    f"`dd of={dest}` replaces what is at that path without "
                    f"asking and without keeping a copy.",
                    safer="Check the path, and add `conv=excl` so `dd` refuses "
                          "to write over something that already exists.",
                    stages=(stage.root,), category="destroy"))

        if stage.command.startswith("mkfs"):
            where = next((o for o in stage.operands if o.startswith("/dev/")),
                         "the named device")
            out.append(Finding(
                Severity.ALERT,
                "This creates an empty filesystem over whatever is there",
                f"`{stage.command}` writes a fresh, empty filesystem onto "
                f"{where}. Everything the device held becomes unreachable the "
                f"moment it finishes.",
                safer="Nothing. Verify the device name, twice, and have the "
                      "backup in your hand before you run it.",
                stages=(stage.root,), category="disk"))

        if stage.command == "wipefs" and stage.has_flag("-a", "--all"):
            out.append(Finding(
                Severity.ALERT,
                "This erases the signatures that identify a filesystem",
                "`wipefs -a` removes the markers the system uses to recognise "
                "what is on a device. The data is still physically there and "
                "nothing can find it.",
                safer="Back up the signatures first: `wipefs --backup`.",
                stages=(stage.root,), category="disk"))

        for redirect in stage.redirects:
            if redirect.writes and BLOCK_DEVICE.match(redirect.target or ""):
                out.append(Finding(
                    Severity.ALERT,
                    f"Output is redirected onto the device {redirect.target}",
                    f"`{redirect.rendered}` sends this command's output over "
                    f"the raw device. Whatever the first bytes are, they land "
                    f"on top of the partition table.",
                    safer="Redirect to a file.",
                    stages=(stage.root,), category="disk"))

        if stage.command == "shred":
            devices = [t for t in _words(stage) if BLOCK_DEVICE.match(t)]
            if devices:
                out.append(Finding(
                    Severity.ALERT,
                    f"This overwrites the device {devices[0]} repeatedly",
                    "`shred` on a whole device is designed to make recovery "
                    "impossible, and it succeeds.",
                    safer="Shred the one file you mean.",
                    stages=(stage.root,), category="disk"))

        if kind == "disk" and stage.command in ("fdisk", "parted") \
                and not stage.has_flag("-l", "--list"):
            out.append(Finding(
                Severity.NOTICE,
                "This edits a disk's partition table",
                f"{_where(stage).capitalize()} opens a partition editor. A "
                f"written change here affects every filesystem on the disk at "
                f"once.",
                safer="Read the current layout first with `-l`.",
                stages=(stage.root,), category="disk"))
    return out


def rule_fork_bomb(script: Script) -> list[Finding]:
    """A function that calls itself twice, forever."""
    match = FORK_BOMB.search(script.source)
    if not match:
        return []
    return [Finding(
        Severity.ALERT,
        "This is a fork bomb",
        f"`{match.group(0).strip()}` defines a function that calls itself "
        f"twice and backgrounds both copies, then calls it. The number of "
        f"processes doubles as fast as the kernel will allow until nothing "
        f"else on the machine can start — usually including whatever you would "
        f"use to stop it.",
        safer="Nothing here is salvageable. If you want to see what process "
              "limits do, set one with `ulimit -u` in a throwaway virtual "
              "machine.",
        stages=(0,), category="fork-bomb")]


def rule_truncating_writes(script: Script) -> list[Finding]:
    """Writes into a system path, and writes that replace rather than add."""
    out: list[Finding] = []
    for stage in script.walk():
        for redirect in stage.redirects:
            target = redirect.target or ""
            if not redirect.writes or not target:
                continue
            if target.startswith(SYSTEM_WRITE_PREFIXES):
                verb = "replaces" if redirect.truncates else "appends to"
                out.append(Finding(
                    Severity.WARNING,
                    f"This writes into a system path ({target})",
                    f"`{redirect.rendered}` {verb} a file the operating system "
                    f"reads. A mistake here is not a lost document; it is a "
                    f"machine that behaves differently from now on, in a way "
                    f"nothing will remind you about.",
                    safer=f"Keep a copy first: `cp {target} {target}.bak`, and "
                          f"prefer `>>` over `>` so the existing contents "
                          f"survive.",
                    stages=(stage.root,), category="system-write"))
            elif redirect.truncates and target != "/dev/null":
                out.append(Finding(
                    Severity.INFO,
                    f"`>` replaces {target} rather than adding to it",
                    f"A single `>` empties the file before the first byte is "
                    f"written. If {target} already exists, its contents are "
                    f"gone whether this command succeeds or not.",
                    safer=f"Use `>>` to append, or `set -o noclobber` so the "
                          f"shell refuses to overwrite.",
                    stages=(stage.root,), category="destroy"))

        if stage.command == "tee":
            for target in stage.operands:
                if target.startswith(SYSTEM_WRITE_PREFIXES):
                    out.append(Finding(
                        Severity.WARNING,
                        f"This writes into a system path ({target})",
                        f"`tee {target}` writes whatever comes down the pipe "
                        f"into a file the system reads — often with `sudo`, so "
                        f"the write succeeds whatever it contains.",
                        safer="Write to a file in your own directory, read it, "
                              "then move it into place deliberately.",
                        stages=(stage.root,), category="system-write"))

        if stage.command == "truncate" and stage.flag_value("-s") in ("0", "0K"):
            out.append(Finding(
                Severity.WARNING,
                "This empties a file without deleting it",
                f"`truncate -s 0` leaves the file in place and discards every "
                f"byte in it, which is why it is a common way to clear a log "
                f"without the gap a missing file would leave.",
                safer="Rotate the file instead, so the old contents still "
                      "exist somewhere.",
                stages=(stage.root,), category="tracks"))

        if stage.command == "find" and stage.has_flag("-delete"):
            out.append(Finding(
                Severity.WARNING,
                "This deletes every file the search matches",
                f"`find … -delete` removes matches as it walks, with no list "
                f"and no confirmation. Whether that is five files or fifty "
                f"thousand depends entirely on the pattern.",
                safer="Run the same `find` without `-delete` first and read "
                      "the list.",
                stages=(stage.root,), category="destroy"))
    return out


def rule_find_exec(script: Script) -> list[Finding]:
    """``find -exec`` and ``xargs`` turn a list of files into a list of commands."""
    out: list[Finding] = []
    destructive = {"rm", "shred", "chmod", "chown", "mv", "dd", "truncate",
                   "srm"}
    for stage in script.walk():
        if stage.command == "find" and stage.has_flag("-exec", "-execdir"):
            run = next((o for o in stage.operands
                        if o not in (".", "..", "{}", ";", "+")
                        and not o.startswith("-") and is_known(o)), "")
            severe = run in destructive
            out.append(Finding(
                Severity.WARNING if severe else Severity.NOTICE,
                f"This runs `{run or 'a command'}` on every file it matches",
                f"`-exec` turns the search result into a command per file. The "
                f"pattern decides the blast radius, and you only find out how "
                f"wide it was afterwards."
                + (f" `{run}` cannot be undone." if severe else ""),
                safer="Run the `find` alone first. Its output is the exact list "
                      "of things that will be acted on.",
                stages=(stage.root,), category="destroy" if severe else "scope"))

        if stage.command == "xargs":
            run = next((o for o in stage.operands if is_known(o)), "")
            if run in destructive:
                out.append(Finding(
                    Severity.WARNING,
                    f"Whatever comes down the pipe becomes arguments to `{run}`",
                    f"`xargs {run}` builds a command line out of its input. If "
                    f"the stage before it produces a filename you did not "
                    f"expect — or a blank line, or a name with a space in it — "
                    f"`{run}` is handed it anyway.",
                    safer=f"Use `xargs -0` with `find -print0` so names with "
                          f"spaces survive, and `xargs -r` so an empty input "
                          f"runs nothing. Add `-p` to confirm each one.",
                    stages=(stage.root,), category="destroy"))
    return out


# --- permissions and identity ----------------------------------------------

def rule_permissions(script: Script) -> list[Finding]:
    """``chmod 777`` and the other ways to give a file away."""
    out: list[Finding] = []
    for stage in script.walk():
        if stage.command == "chmod":
            recursive = stage.has_flag("-R", "--recursive")
            modes = [o for o in stage.operands
                     if re.fullmatch(r"[0-7]{3,4}", o) or re.search(r"[+=]", o)]
            for mode in modes:
                digits = re.fullmatch(r"([0-7]?)([0-7]{3})", mode)
                world_writable = (
                    (digits and digits.group(2).endswith(("7", "6", "3", "2")))
                    or "o+w" in mode or "a+w" in mode or "a+rwx" in mode)
                if mode.endswith("777") or "a+rwx" in mode:
                    out.append(Finding(
                        Severity.WARNING,
                        "This makes a file readable and writable by everyone",
                        f"Mode `{mode}` lets any account on the machine read, "
                        f"change and run it"
                        + (", and `-R` applies that to every file underneath"
                           if recursive else "")
                        + ". It is the usual response to a permission error, "
                          "and it fixes the error by removing the protection "
                          "rather than by finding out which account needed "
                          "access.",
                        safer="Give the one account that needs it access: "
                              "`chown` it to that user, or add a group and use "
                              "`chmod 750`.",
                        stages=(stage.root,), category="perm"))
                elif world_writable:
                    out.append(Finding(
                        Severity.NOTICE,
                        f"Mode `{mode}` lets any account write to this",
                        "Anything world-writable can be replaced by any user "
                        "on the machine, including a process that is not "
                        "supposed to be able to.",
                        safer="Drop the last digit to 4 or 5, or use a group.",
                        stages=(stage.root,), category="perm"))
                if digits and digits.group(1) in ("2", "4", "6"):
                    out.append(Finding(
                        Severity.WARNING,
                        f"Mode `{mode}` sets the setuid or setgid bit",
                        "A setuid program runs as its owner, not as whoever "
                        "started it. On a file anyone can write to, that is a "
                        "way for any user on the machine to become its owner.",
                        safer="Leave the leading digit off unless you are "
                              "deliberately writing a privileged helper.",
                        stages=(stage.root,), category="perm"))
            for target in stage.operands:
                if recursive and (_strip_path(target) in SYSTEM_DIRS
                                  or target in ROOTISH):
                    out.append(Finding(
                        Severity.ALERT,
                        f"This rewrites the permissions of {target} and "
                        f"everything under it",
                        "A recursive `chmod` across a system directory "
                        "overwrites the permissions the operating system "
                        "relies on. There is no record of what they were, so "
                        "there is nothing to restore them from.",
                        safer="Change the one path that needs changing.",
                        stages=(stage.root,), category="perm"))

        if stage.command in ("chown", "chgrp") and stage.has_flag("-R"):
            outside = [t for t in stage.operands
                       if t.startswith("/") and not t.startswith(HOME_PREFIXES)
                       and ":" not in t]
            if outside:
                out.append(Finding(
                    Severity.NOTICE,
                    f"This changes who owns {outside[0]}, recursively",
                    "Ownership outside a home directory is usually set by the "
                    "package that installed the files. Changing it can make a "
                    "service refuse to start, and nothing records what the "
                    "owner used to be.",
                    safer="Note the current owner first: `ls -ld "
                          f"{outside[0]}`.",
                    stages=(stage.root,), category="perm"))

        if stage.command == "setenforce" and "0" in stage.operands:
            out.append(Finding(
                Severity.WARNING,
                "This turns SELinux enforcement off",
                "With enforcement off, the policy that confines each service "
                "to its own files stops being applied. Everything keeps "
                "working, which is why it is a common way to make a problem "
                "appear to go away.",
                safer="Find the denial instead: `ausearch -m AVC -ts recent`, "
                      "and fix the label or add a rule.",
                stages=(stage.root,), category="defence"))

        if stage.command == "chattr" and "-i" in stage.flags:
            out.append(Finding(
                Severity.NOTICE,
                "This removes a file's immutable attribute",
                "The immutable bit is set to stop a file being changed even by "
                "root. Clearing it is the step before changing something that "
                "was deliberately locked.",
                safer="Find out who set it, and why, before you clear it.",
                stages=(stage.root,), category="perm"))
    return out


def rule_elevation(script: Script) -> list[Finding]:
    """Who gets to be root, and what they are handed."""
    out: list[Finding] = []
    elevated = [s for s in script.walk() if s.elevated]

    if elevated:
        named = "; ".join(_where(s) for s in elevated[:4])
        whole = len(elevated) == len(list(script.walk()))
        out.append(Finding(
            Severity.NOTICE,
            "This whole line runs as root" if whole
            else "Part of this line runs as root",
            f"Root runs at {named}. Every check that would normally stop a "
            f"command — file permissions, ownership, the refusal to touch "
            f"another user's data — stops applying there.",
            safer="Give root the narrowest possible command. Elevate the one "
                  "step that needs it, not the whole line.",
            stages=tuple(sorted({s.root for s in elevated})),
            category="privilege"))

    for stage in script.walk():
        if stage.elevated and stage.is_piped_in:
            out.append(Finding(
                Severity.WARNING,
                "Data is piped into a command running as root",
                f"The output of the stage before it becomes the input of "
                f"`{stage.command}` running as root. The unprivileged half of "
                f"the line decides what the privileged half does, which is the "
                f"opposite of what elevating one command is for.",
                safer="Capture the output to a file, read it, and then run the "
                      "privileged step on the file.",
                stages=(stage.root,), category="privilege"))
        if stage.elevated and (
                "-S" in stage.argv or "--stdin" in stage.argv):
            out.append(Finding(
                Severity.WARNING,
                "sudo is told to read your password from the pipe",
                "`sudo -S` takes the password from standard input rather than "
                "from the terminal. That means the password is written down "
                "somewhere in this line, or in whatever produced it.",
                safer="Let sudo prompt you. If this is automation, give the "
                      "account a narrow sudoers rule with NOPASSWD instead of "
                      "storing a password.",
                stages=(stage.root,), category="privilege"))
    return out


# --- transport and trust ----------------------------------------------------

def rule_tls_disabled(script: Script) -> list[Finding]:
    """Every spelling of "do not check the certificate"."""
    out: list[Finding] = []
    for stage in script.walk():
        reason = ""
        if stage.command in ("curl",) and stage.has_flag("-k", "--insecure"):
            reason = "`-k` tells curl to accept any certificate at all"
        elif "--no-check-certificate" in stage.flags:
            reason = "`--no-check-certificate` turns the check off entirely"
        elif any("sslverify=false" in t.lower() for t in _tokens(stage)):
            reason = "`http.sslVerify=false` turns Git's check off"
        elif any("strict-ssl=false" in t.lower() for t in _tokens(stage)):
            reason = "`--strict-ssl=false` turns npm's check off"
        elif stage.has_flag("--trusted-host"):
            reason = "`--trusted-host` tells pip to skip verification for a host"
        elif "--allow-unauthenticated" in stage.flags or \
                "--force-yes" in stage.flags:
            reason = "the package signature check is being waived"
        elif any(t.lower() in ("--check-certificate=false", "--insecure")
                 for t in stage.flags):
            reason = "certificate checking is switched off"
        if not reason:
            continue
        out.append(Finding(
            Severity.WARNING,
            "Certificate checking is switched off for this transfer",
            f"{reason}. The encryption still happens, but you no longer know "
            f"who you are talking to — which is the part that was protecting "
            f"you. Anyone able to answer in the server's place can serve "
            f"whatever they like.",
            safer="Fix the certificate instead. If it is a private CA, point "
                  "the tool at its root certificate rather than disabling the "
                  "check.",
            stages=(stage.root,), category="tls"))
    return out


def rule_plain_http(script: Script) -> list[Finding]:
    """Content fetched in clear text, and worse if it is then executed."""
    out: list[Finding] = []
    for pipeline in script.pipelines():
        positions = {id(s): i for i, s in enumerate(pipeline)}
        runners = _runners(pipeline)
        for stage in pipeline:
            plain = [u for u in _urls(stage) if u.lower().startswith("http://")]
            if not plain:
                continue
            executed = any(positions[id(r)] > positions[id(stage)]
                           for r in runners) or bool(
                [c for child in stage.inner for c in child.walk()])
            if executed:
                out.append(Finding(
                    Severity.WARNING,
                    "Code is fetched over plain HTTP and then run",
                    f"{plain[0]} has no encryption and no proof of who is "
                    f"answering. Any network between you and that host — a "
                    f"café, a hotel, a compromised router — can replace the "
                    f"script in flight with its own, and nothing in this line "
                    f"would notice.",
                    safer="Use the `https://` form of the same URL. If the host "
                          "does not offer one, do not run what it sends.",
                    stages=(stage.root,), category="transport"))
            else:
                out.append(Finding(
                    Severity.NOTICE,
                    "This downloads over plain HTTP",
                    f"{plain[0]} travels in clear text, so what arrives is not "
                    f"necessarily what was sent, and anyone on the path can "
                    f"read it.",
                    safer="Use `https://`, and check the file's published "
                          "checksum after it lands.",
                    stages=(stage.root,), category="transport"))
    return out


def rule_host_key_checking(script: Script) -> list[Finding]:
    """Turning off the one thing that tells you which machine answered."""
    out: list[Finding] = []
    for stage in script.walk():
        joined = " ".join(_tokens(stage)).lower() + " " + stage.raw.lower()
        if "stricthostkeychecking=no" in joined.replace(" ", ""):
            out.append(Finding(
                Severity.WARNING,
                "SSH is told not to check the host key",
                "`StrictHostKeyChecking=no` makes SSH accept whatever key the "
                "far end offers, silently, every time. The host key is the "
                "only thing proving you reached the machine you meant; "
                "without it an interception looks exactly like a normal "
                "connection.",
                safer="Record the real key once — `ssh-keyscan host >> "
                      "~/.ssh/known_hosts` after checking it out of band — or "
                      "use `accept-new`, which trusts the first key and still "
                      "warns when it changes.",
                stages=(stage.root,), category="trust"))
        elif "stricthostkeychecking=accept-new" in joined.replace(" ", ""):
            out.append(Finding(
                Severity.NOTICE,
                "SSH will trust whichever key it sees first",
                "`accept-new` is the lesser of the two: it records the key the "
                "first time without asking, but it still warns you if it ever "
                "changes.",
                safer="Verify the fingerprint out of band for anything that "
                      "matters.",
                stages=(stage.root,), category="trust"))
        if "userknownhostsfile=/dev/null" in joined.replace(" ", ""):
            out.append(Finding(
                Severity.WARNING,
                "SSH is told to forget the host key afterwards",
                "Sending the known-hosts file to `/dev/null` means nothing is "
                "remembered, so no future connection can ever notice that the "
                "key changed.",
                safer="Use a real known-hosts file, even a per-project one.",
                stages=(stage.root,), category="trust"))
        if stage.command == "ssh":
            remote = [o for o in stage.operands
                      if "@" not in o and not o.startswith("-")
                      and o not in ("StrictHostKeyChecking=no",)
                      and " " in o]
            if remote:
                out.append(Finding(
                    Severity.NOTICE,
                    "The quoted command runs on the remote machine",
                    f"`{remote[0]}` is executed on the far side, not here. "
                    f"Caveat has read it as a command line, but every path in "
                    f"it means whatever it means over there.",
                    safer="Run it interactively on that machine first, where "
                          "you can see the result.",
                    stages=(stage.root,), category="scope"))
        if stage.command == "ssh" and stage.has_flag("-A"):
            out.append(Finding(
                Severity.NOTICE,
                "Your SSH agent is forwarded to the remote machine",
                "Agent forwarding lets anything with root on the far side use "
                "your keys, for as long as you are connected, to reach "
                "anywhere those keys open.",
                safer="Use `ssh -J` (a jump host) instead, which does not "
                      "expose the agent.",
                stages=(stage.root,), category="trust"))
    return out


def rule_reverse_shell(script: Script) -> list[Finding]:
    """A shell wired to a socket — the shape, in all its usual spellings."""
    out: list[Finding] = []
    for stage in script.walk():
        tokens = _tokens(stage)
        joined = " ".join(tokens) + " " + stage.raw

        if stage.command in ("nc", "ncat", "netcat") and \
                stage.has_flag("-e", "-c"):
            out.append(Finding(
                Severity.ALERT,
                "This wires a program to a network connection",
                f"`{stage.command} -e` runs a program and connects its input "
                f"and output to the socket. When that program is a shell, "
                f"whoever is on the other end has a command prompt on this "
                f"machine, as you, with no password.",
                safer="There is no safe version of this on a machine you care "
                      "about. For remote access use SSH, which authenticates "
                      "both ends.",
                stages=(stage.root,), category="backdoor"))

        if "/dev/tcp/" in joined or "/dev/udp/" in joined:
            out.append(Finding(
                Severity.ALERT,
                "A shell's input and output are attached to a network socket",
                "Bash can open a socket as if it were a file. Redirecting an "
                "interactive shell onto one hands the prompt to whoever is "
                "listening at the other end — which is why this exact form "
                "appears in nearly every published reverse-shell list.",
                safer="Nothing. If you need a remote prompt, use SSH.",
                stages=(stage.root,), category="backdoor"))

        if stage.command == "socat" and any(
                re.search(r"\b(exec|system)\s*:", t, re.I) for t in tokens):
            out.append(Finding(
                Severity.ALERT,
                "socat is told to run a program on one end of the connection",
                "`EXEC:` and `SYSTEM:` make socat start a process and join it "
                "to the other address, which is usually a socket. The result "
                "is an unauthenticated command channel.",
                safer="Use SSH for remote execution.",
                stages=(stage.root,), category="backdoor"))

        if kind_of(stage.command) == "interp":
            lowered = joined.lower()
            if "socket" in lowered and any(
                    w in lowered for w in ("connect", "dup2", "bind")):
                out.append(Finding(
                    Severity.ALERT,
                    "This inline program opens a socket and attaches a shell",
                    f"A one-line {stage.command} program that creates a socket "
                    f"and duplicates it onto the standard streams is a reverse "
                    f"shell written in a language that happens to be "
                    f"installed.",
                    safer="Read the program on its own, laid out over several "
                          "lines, before deciding what it does.",
                    stages=(stage.root,), category="backdoor"))

        if stage.command in ("nc", "ncat", "netcat") and stage.has_flag("-l") \
                and not stage.has_flag("-e", "-c"):
            out.append(Finding(
                Severity.NOTICE,
                "This opens a listening port on this machine",
                f"`{stage.command} -l` waits for an incoming connection. "
                f"Anyone who can reach the port can connect; there is no "
                f"authentication of any kind.",
                safer="Bind it to localhost, and stop it when you are done.",
                stages=(stage.root,), category="network"))
    return out


# --- the record of what happened -------------------------------------------

def rule_covering_tracks(script: Script) -> list[Finding]:
    """Anything whose effect is that nobody can tell what was done."""
    out: list[Finding] = []
    seen: set[str] = set()

    def add(title: str, detail: str, safer: str, stage: Stage) -> None:
        if title in seen:
            return
        seen.add(title)
        out.append(Finding(Severity.WARNING, title, detail, safer=safer,
                           stages=(stage.root,), category="tracks"))

    for stage in script.walk():
        tokens = " ".join(_tokens(stage) + stage.assignments)

        if stage.command == "history" and stage.has_flag("-c", "-d", "-w"):
            add("This erases the shell's record of what was typed",
                "`history -c` empties the list this shell is holding, and "
                "`-w` then writes that empty list over the history file. "
                "Afterwards there is nothing to show what ran, including the "
                "command that did the erasing.",
                "If a secret was typed by mistake, remove the one entry with "
                "`history -d <number>` and change the secret — the secret is "
                "the problem, not the record of it.", stage)

        if stage.command == "unset" and "HISTFILE" in stage.operands:
            add("This stops the shell writing a history file",
                "With `HISTFILE` unset, nothing this shell does from now on is "
                "recorded. It is the standard first line of a session somebody "
                "does not want reconstructed.",
                "Leave history on. If a command would contain a secret, pass "
                "the secret in a file or an environment variable instead.",
                stage)

        if re.search(r"\bHIST(FILE|SIZE|FILESIZE)\s*=\s*(/dev/null|0|\"\"|'')?",
                     tokens + " " + stage.raw):
            if "HISTFILE=/dev/null" in tokens.replace(" ", "") or \
                    re.search(r"\bHIST(SIZE|FILESIZE)\s*=\s*0\b", stage.raw):
                add("Shell history is being sent nowhere",
                    "Pointing `HISTFILE` at `/dev/null`, or setting the "
                    "history size to zero, keeps the shell working exactly as "
                    "before while recording nothing.",
                    "Leave the history alone and keep secrets out of command "
                    "lines instead.", stage)

        if re.search(r"set\s+\+o\s+history", stage.raw):
            add("History recording is switched off for this shell",
                "`set +o history` stops this shell adding anything further to "
                "its history, quietly, until it is switched back on.",
                "Leave it on.", stage)

        if stage.command in ("rm", "shred", "truncate", "srm"):
            hit = next((t for t in _words(stage)
                        if any(p in t for p in LOG_PATHS)), "")
            if hit:
                add(f"This removes or empties a log ({hit})",
                    "Logs are how anybody — including you, next week — works "
                    "out what happened on a machine. Deleting them is "
                    "indistinguishable from tidying up, which is exactly why "
                    "it is worth saying out loud.",
                    "If the log is large, rotate it with `logrotate` so the "
                    "old contents still exist somewhere.", stage)

        if stage.command == "journalctl" and stage.has_flag(
                "--vacuum-time", "--vacuum-size"):
            add("This deletes entries from the system journal",
                "`--vacuum-time` and `--vacuum-size` discard journal records "
                "permanently. Disk pressure is a real reason to do it; so is "
                "removing the record of something.",
                "Export what you need first: `journalctl --since … > "
                "journal.txt`.", stage)
    return out


# --- later, and elsewhere ---------------------------------------------------

def rule_persistence(script: Script) -> list[Finding]:
    """Things that keep running after you stop watching."""
    out: list[Finding] = []
    for stage in script.walk():
        if stage.command == "crontab":
            if stage.has_flag("-r"):
                out.append(Finding(
                    Severity.WARNING,
                    "This removes every scheduled job for the user",
                    "`crontab -r` deletes the whole table at once, with no "
                    "confirmation and no copy. Whatever was scheduled — "
                    "backups included — stops happening.",
                    safer="Save it first: `crontab -l > cron.bak`.",
                    stages=(stage.root,), category="persistence"))
            elif stage.has_flag("-e") or "-" in stage.operands or \
                    stage.operands:
                out.append(Finding(
                    Severity.NOTICE,
                    "This installs a command that will run on a schedule",
                    f"A cron entry runs on its own, at times nobody is "
                    f"watching, for as long as the account exists. It is the "
                    f"most durable thing a single command line can leave "
                    f"behind.",
                    safer="Read the existing table first with `crontab -l`, "
                          "and keep a copy of it.",
                    stages=(stage.root,), category="persistence"))

        if stage.command in ("at", "systemd-run"):
            out.append(Finding(
                Severity.NOTICE,
                "This arranges for something to run later",
                f"`{stage.command}` detaches the work from this terminal, so "
                f"it happens whether or not you are here to see the result.",
                safer="Note what you scheduled, and how to list it again "
                      "(`atq`, or `systemctl list-units --all`).",
                stages=(stage.root,), category="persistence"))

        if stage.command == "systemctl":
            if "enable" in stage.operands:
                out.append(Finding(
                    Severity.NOTICE,
                    "This makes a service start at every boot",
                    "An enabled unit comes back after a restart, which is the "
                    "point — and also means a mistake survives the reboot you "
                    "would otherwise use to clear it.",
                    safer="Try it with `systemctl start` first and leave "
                          "`enable` until it behaves.",
                    stages=(stage.root,), category="persistence"))
            for word in ("stop", "disable", "mask"):
                if word in stage.operands:
                    out.append(Finding(
                        Severity.NOTICE,
                        f"This turns a system service off (`{word}`)",
                        f"`systemctl {word}` stops a service running"
                        + (" and makes it impossible to start again until it "
                           "is unmasked" if word == "mask" else "")
                        + ". Whatever depended on it stops working too, "
                          "possibly not immediately.",
                        safer="Check what wants it first: `systemctl "
                              "list-dependencies --reverse <unit>`.",
                        stages=(stage.root,), category="service"))
                    break

        if stage.background:
            out.append(Finding(
                Severity.NOTICE,
                "This keeps running after the line returns",
                f"The trailing `&` detaches {_where(stage)} from your prompt. "
                f"It carries on in the background, and its output may arrive "
                f"later, mixed into whatever you are reading.",
                safer="Leave the `&` off until you have seen it work, or run "
                      "it under `screen`/`tmux` where you can look at it.",
                stages=(stage.root,), category="lifecycle"))
    return out


def rule_firewall(script: Script) -> list[Finding]:
    """Switching off a defence, as opposed to configuring one."""
    out: list[Finding] = []
    for stage in script.walk():
        if stage.command == "ufw" and "disable" in stage.operands:
            out.append(Finding(
                Severity.WARNING,
                "This turns the host firewall off",
                "With the firewall down, every port a program happens to be "
                "listening on becomes reachable from the network — including "
                "the ones you have forgotten about.",
                safer="Open the single port you need: `ufw allow 8080/tcp`.",
                stages=(stage.root,), category="defence"))
        if stage.command == "iptables" and stage.has_flag("-F"):
            out.append(Finding(
                Severity.WARNING,
                "This deletes every firewall rule in the chain",
                "`iptables -F` flushes the rules. If the default policy is "
                "ACCEPT — and it usually is — the machine is wide open the "
                "instant it finishes, and stays that way until something "
                "reloads the rules.",
                safer="Save the current rules first: `iptables-save > "
                      "rules.v4`.",
                stages=(stage.root,), category="defence"))
        if stage.command == "iptables" and stage.has_flag("-P") and \
                any(o.upper() == "ACCEPT" for o in stage.operands):
            out.append(Finding(
                Severity.WARNING,
                "This sets a firewall chain's default to accept everything",
                "A default policy of ACCEPT means anything not explicitly "
                "blocked gets through, which inverts how a firewall is meant "
                "to be read.",
                safer="Default to DROP and allow what you need by name.",
                stages=(stage.root,), category="defence"))
        if stage.command == "nft" and "flush" in stage.operands:
            out.append(Finding(
                Severity.WARNING,
                "This flushes the entire packet-filter ruleset",
                "`nft flush ruleset` removes every rule on the machine at "
                "once.",
                safer="Keep a copy: `nft list ruleset > rules.nft`.",
                stages=(stage.root,), category="defence"))
    return out


def rule_processes(script: Script) -> list[Finding]:
    """Signals aimed widely."""
    out: list[Finding] = []
    for stage in script.walk():
        aimed = stage.flags + stage.operands
        if stage.command == "kill" and stage.has_flag("-9", "-KILL") and \
                any(o in ("-1", "1") for o in aimed):
            target = "every process you own" if "-1" in aimed \
                else "process 1, the init process"
            out.append(Finding(
                Severity.ALERT,
                f"This sends an unblockable kill to {target}",
                "SIGKILL cannot be caught, so nothing gets to save its work or "
                "close a file cleanly. Aimed this widely it takes the session, "
                "and possibly the machine, down with it.",
                safer="Name the one process, and try `kill` without `-9` "
                      "first so it can shut down properly.",
                stages=(stage.root,), category="process"))
        elif stage.command in ("killall", "pkill") and \
                stage.has_flag("-9", "-KILL"):
            out.append(Finding(
                Severity.NOTICE,
                f"This kills every process matching a pattern, unblockably",
                f"`{stage.command}` matches by name, and `-9` means no process "
                f"it matches gets to clean up. A broad pattern takes things "
                f"you did not mean.",
                safer="List the matches first: `pgrep -a <pattern>`.",
                stages=(stage.root,), category="process"))
    return out


def rule_containers(script: Script) -> list[Finding]:
    """A container is a boundary; these are the ways to remove it."""
    out: list[Finding] = []
    for stage in script.walk():
        if stage.command not in ("docker", "podman"):
            continue
        if stage.has_flag("--privileged"):
            out.append(Finding(
                Severity.WARNING,
                "The container is given the host's own powers",
                "`--privileged` removes nearly every boundary a container has: "
                "it can see the host's devices and change its kernel "
                "settings. Anything inside it is effectively running on the "
                "host as root.",
                safer="Grant the one capability it needs instead: `--cap-add "
                      "NET_ADMIN`, for example.",
                stages=(stage.root,), category="container"))
        for mount in [t for t in _tokens(stage) if ":" in t]:
            source = mount.split(":", 1)[0]
            if source == "/" or source in SYSTEM_DIRS:
                out.append(Finding(
                    Severity.WARNING,
                    f"The host path {source} is mounted into the container",
                    f"Anything in the container can read and write {source} as "
                    f"it appears on the host, so the container's isolation no "
                    f"longer protects those files.",
                    safer="Mount the single directory the program needs, and "
                          "add `:ro` to make it read-only.",
                    stages=(stage.root,), category="container"))
                break
            if "docker.sock" in source:
                out.append(Finding(
                    Severity.WARNING,
                    "The Docker socket is mounted into the container",
                    "A process that can talk to the Docker socket can start "
                    "another container with any options it likes, including "
                    "one that mounts the host's root filesystem. It is "
                    "equivalent to giving it root on the host.",
                    safer="Use a scoped API proxy, or keep the work outside "
                          "the container.",
                    stages=(stage.root,), category="container"))
                break
        if any(t in ("--net=host", "--network=host") for t in _tokens(stage)) \
                or stage.flag_value("--net", "--network") == "host":
            out.append(Finding(
                Severity.NOTICE,
                "The container shares the host's network",
                "With host networking there is no port mapping and no network "
                "namespace: anything the container listens on is listening on "
                "the host itself.",
                safer="Publish the one port you need with `-p 8080:8080`.",
                stages=(stage.root,), category="container"))
    return out


def rule_supply_chain(script: Script) -> list[Finding]:
    """Where the installed code is coming from, and what it runs on arrival."""
    out: list[Finding] = []
    for stage in script.walk():
        if stage.command in ("pip", "pip3") and "install" in stage.operands:
            if stage.has_flag("--index-url", "--extra-index-url"):
                out.append(Finding(
                    Severity.NOTICE,
                    "Packages are fetched from a different index",
                    "A replacement index decides which code answers to a "
                    "package name. If a name exists in both places, the one "
                    "you get depends on configuration rather than on intent.",
                    safer="Pin the exact versions, and keep the private index "
                          "to the packages that are actually private.",
                    stages=(stage.root,), category="supply-chain"))
            remote = [o for o in stage.operands
                      if o.startswith(("git+", "http://", "https://"))]
            if remote:
                out.append(Finding(
                    Severity.NOTICE,
                    "A package is installed straight from a URL",
                    f"`{remote[0]}` is not a release from the index — it is "
                    f"whatever that location holds at the moment you install, "
                    f"and it runs its own setup code as it installs.",
                    safer="Install a pinned version from the index, or clone "
                          "the repository and read it first.",
                    stages=(stage.root,), category="supply-chain"))
            if stage.has_flag("--break-system-packages"):
                out.append(Finding(
                    Severity.NOTICE,
                    "This installs into the system's own Python",
                    "The flag exists because the distribution asked pip not to "
                    "do this: packages installed here can replace ones the "
                    "package manager owns, and the two will disagree later.",
                    safer="Use a virtual environment: `python3 -m venv .venv`.",
                    stages=(stage.root,), category="supply-chain"))

        if stage.command in ("npm", "yarn") and (
                "install" in stage.operands or "i" in stage.operands or
                not stage.operands):
            if not stage.has_flag("--ignore-scripts"):
                out.append(Finding(
                    Severity.INFO,
                    "Installing runs each package's own install scripts",
                    "An npm package may define scripts that run as part of "
                    "installation, as you, with no further prompt. That is "
                    "normal and documented — it is also why `npm install` is "
                    "not a read-only operation.",
                    safer="Add `--ignore-scripts` when you only need the files, "
                          "and keep a lockfile so you install what you "
                          "reviewed.",
                    stages=(stage.root,), category="supply-chain"))
            if stage.has_flag("-g", "--global") or \
                    stage.has_flag("--unsafe-perm"):
                out.append(Finding(
                    Severity.NOTICE,
                    "This installs system-wide",
                    "A global install puts the package, and its install "
                    "scripts, outside any one project — often under `sudo`, "
                    "which means those scripts run as root.",
                    safer="Install into the project and run it with `npx`, so "
                          "the version is recorded alongside the code.",
                    stages=(stage.root,), category="supply-chain"))

        if stage.command == "curl" and any(
                s.command == "chmod" and any("+x" in f for f in s.operands)
                for s in script.walk()):
            out.append(Finding(
                Severity.NOTICE,
                "A downloaded file is made executable",
                "The line fetches something and then marks it runnable. That "
                "is the normal way to install a binary, and also the normal "
                "way to install one you have not inspected.",
                safer="Check the publisher's checksum or signature against the "
                      "file before you set the executable bit.",
                stages=(stage.root,), category="supply-chain"))
            break
    return out


# --- what Caveat cannot tell -----------------------------------------------

def rule_quoting(script: Script) -> list[Finding]:
    """Unquoted expansions: the bug that only shows up on the wrong input."""
    out: list[Finding] = []
    reported: set[str] = set()
    for stage in script.walk():
        bare = unquoted_text(stage.raw)
        for match in VARIABLE.finditer(bare):
            token = match.group(0)
            if token in _STATUS_VARS:
                continue
            name = match.group(1)
            if token in reported:
                continue
            if re.search(re.escape(token) + r"\s*=", bare):
                continue
            reported.add(token)
            if name in ("@", "*"):
                out.append(Finding(
                    Severity.NOTICE,
                    f"`{token}` is used without quotes",
                    f"Unquoted, `{token}` is re-split on spaces, so an "
                    f"argument that contained one arrives as two. Written "
                    f"`\"{token}\"` it keeps every argument exactly as it was "
                    f"given.",
                    safer=f"Write `\"{token}\"`.",
                    stages=(stage.root,), category="quoting"))
            else:
                out.append(Finding(
                    Severity.NOTICE,
                    f"`{token}` is expanded without quotes",
                    f"Caveat cannot know what `{token}` holds, and neither can "
                    f"this line. If it contains a space the shell splits it "
                    f"into two arguments; if it is empty the argument "
                    f"disappears and the command runs on whatever is left.",
                    safer=f"Quote it: `\"{token}\"`.",
                    stages=(stage.root,), category="quoting"))
    return out


def rule_unknown(script: Script) -> list[Finding]:
    """What Caveat does not recognise, said plainly rather than guessed at."""
    out: list[Finding] = []
    unknown: list[Stage] = []
    local = locally_defined(script)
    for stage in script.walk():
        if "$" in stage.command or "`" in stage.command:
            out.append(Finding(
                Severity.WARNING,
                "The command itself comes from an expansion",
                f"The first word of {_where(stage)} is `{stage.command}`, which "
                f"the shell works out at the moment it runs. Nothing in this "
                f"line says what will actually be executed.",
                safer="Print it first, or write the command out literally.",
                stages=(stage.root,), category="unknown"))
            continue
        if is_function_definition(stage):
            out.append(Finding(
                Severity.INFO,
                "This defines a shell function before calling it",
                f"`{stage.command}` is the head of a function definition, not "
                f"a program. The body is what runs, every time the name is "
                f"used later in the line.",
                safer="Read the body first, and look for a call to the name "
                      "further along the line.",
                stages=(stage.root,), category="unknown"))
            continue
        if stage.command in local:
            out.append(Finding(
                Severity.INFO,
                f"`{stage.command}` is a function defined on this same line",
                "The name is not a program; it is defined a few words earlier. "
                "What runs is the body of that definition, which Caveat has "
                "read as its own stages above.",
                safer="Read the definition, not just the call.",
                stages=(stage.root,), category="unknown"))
        elif not is_known(stage.command):
            unknown.append(stage)
        if "/" in stage.command_path:
            out.append(Finding(
                Severity.INFO,
                f"This runs a program by path (`{stage.command_path}`)",
                "Naming a path skips `PATH` entirely, which is usually "
                "deliberate. Caveat can tell you what the name means; it "
                "cannot see what that particular file contains.",
                safer=f"Check it before you run it: `file "
                      f"{stage.command_path}` and `head {stage.command_path}`.",
                stages=(stage.root,), category="unknown"))

    if unknown:
        names = sorted({s.command for s in unknown})
        listed = ", ".join(f"`{n}`" for n in names[:6])
        out.append(Finding(
            Severity.INFO,
            f"Caveat has no entry for {listed}",
            f"{'This command is' if len(names) == 1 else 'These commands are'} "
            f"not in Caveat's dictionary, so nothing below describes "
            f"{'it' if len(names) == 1 else 'them'}. That is a gap in the "
            f"tool, not a verdict on the command — and it is why this reading "
            f"cannot be called routine.",
            safer=f"Read the manual page first: `man {names[0]}`, or `{names[0]}"
                  f" --help`.",
            stages=tuple(sorted({s.root for s in unknown})),
            category="unknown"))
    return out


def rule_parse_trouble(script: Script) -> list[Finding]:
    """When the text itself did not come apart cleanly."""
    out: list[Finding] = []
    for stage in script.walk():
        if not stage.quote_error:
            continue
        out.append(Finding(
            Severity.NOTICE,
            "The quoting in this line does not close",
            f"Caveat could not split {_where(stage)} the way a shell would, "
            f"because a quote or bracket is left open. Everything it says "
            f"about this stage is a best guess, and your shell may well split "
            f"it somewhere else.",
            safer="Close the quote, or paste the whole line rather than part "
                  "of it.",
            stages=(stage.root,), category="parse"))
    return out


def rule_interpreter_inline(script: Script) -> list[Finding]:
    """A program written inline, in a language Caveat does not read."""
    out: list[Finding] = []
    for stage in script.walk():
        if kind_of(stage.command) != "interp":
            continue
        inline = [o for o in stage.operands if len(o) > 12 and
                  any(c in o for c in "();=")]
        if not inline:
            continue
        out.append(Finding(
            Severity.NOTICE,
            f"A {stage.command} program is written inline",
            f"{_where(stage).capitalize()} carries a whole program as one "
            f"argument. Caveat reads shell, not {stage.command}: it can tell "
            f"you that a program runs here, but not what it does.",
            safer=f"Put it in a file and read it: it will be easier to follow "
                  f"on more than one line, and `{stage.command}` will run it "
                  f"just the same.",
            stages=(stage.root,), category="unknown"))
    return out


# --- the narrow, checkable good news ---------------------------------------

def rule_reassurances(script: Script) -> list[Finding]:
    """Properties worth stating because they were checked, not because they
    add up to approval."""
    out: list[Finding] = []
    stages = list(script.walk())
    if not stages:
        return out

    local = locally_defined(script)
    named = [s for s in stages
             if not is_function_definition(s) and s.command not in local]
    if all(is_known(s.command) for s in named) and \
            not any("$" in s.command for s in stages):
        out.append(Finding(
            Severity.GOOD,
            "Every command here is one Caveat recognises",
            f"All {len(named)} stage{'' if len(named) == 1 else 's'} matched "
            f"an entry in the dictionary, so the sentences below describe the "
            f"real commands rather than guesses at them.",
            stages=(), category="known"))

    if not any(s.elevated for s in stages):
        out.append(Finding(
            Severity.GOOD,
            "Nothing on this line asks for root",
            "No `sudo`, `doas`, `su` or `pkexec` appears, so whatever this "
            "does, it does with your own permissions and no more.",
            stages=(), category="privilege"))

    if all(_is_read_only(s) for s in stages):
        out.append(Finding(
            Severity.GOOD,
            "Nothing on this line writes, deletes or installs",
            "Every command here only reports: it reads files or process "
            "state and prints what it finds.",
            stages=(), category="scope"))

    fetchers = [s for s in stages if kind_of(s.command) == FETCH]
    if fetchers:
        runners = _runners(stages)
        to_file = any(f.has_flag("-o", "-O", "--output", "-P")
                      or any(r.writes for r in f.redirects) for f in fetchers)
        if to_file and not runners:
            out.append(Finding(
                Severity.GOOD,
                "The download lands in a file, not in a shell",
                "The fetched bytes are written to disk, where you can look at "
                "them, check them against a published checksum, and decide "
                "separately whether to run anything.",
                stages=tuple(f.root for f in fetchers), category="remote-exec"))
        urls = [u for f in fetchers for u in _urls(f)]
        insecure = any(f.has_flag("-k", "--insecure") or
                       "--no-check-certificate" in f.flags for f in fetchers)
        if urls and all(u.lower().startswith("https://") for u in urls) \
                and not insecure:
            out.append(Finding(
                Severity.GOOD,
                "The transfer is over HTTPS with verification left on",
                "The URL is `https://` and no flag turns the certificate check "
                "off, so the bytes are encrypted in transit and the server "
                "proved which host it is.",
                stages=tuple(f.root for f in fetchers), category="tls"))
    return out


# --- the register -----------------------------------------------------------

RULES: list[Rule] = [
    rule_download_into_shell,
    rule_runs_substituted_download,
    rule_decoded_into_shell,
    rule_fork_bomb,
    rule_recursive_delete,
    rule_disk_destruction,
    rule_truncating_writes,
    rule_find_exec,
    rule_permissions,
    rule_elevation,
    rule_tls_disabled,
    rule_plain_http,
    rule_host_key_checking,
    rule_reverse_shell,
    rule_covering_tracks,
    rule_persistence,
    rule_firewall,
    rule_processes,
    rule_containers,
    rule_supply_chain,
    rule_eval,
    rule_long_encoded_blob,
    rule_quoting,
    rule_interpreter_inline,
    rule_unknown,
    rule_parse_trouble,
    rule_reassurances,
]


def run(script: Script) -> list[Finding]:
    """Every rule, de-duplicated, most serious first.

    The sort is stable, so within one severity the findings stay in the order
    the register puts them: the thing that destroys data before the thing that
    merely surprises you.
    """
    found: list[Finding] = []
    seen: set[tuple] = set()
    for rule in RULES:
        for finding in rule(script):
            key = (finding.severity, finding.title, finding.stages)
            if key in seen:
                continue
            seen.add(key)
            found.append(finding)
    return sorted(found, key=lambda f: -f.severity.rank)
