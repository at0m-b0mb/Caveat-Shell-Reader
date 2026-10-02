<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="images/banner-dark.png">
  <img src="images/banner.png" alt="Caveat — read before you run" width="100%">
</picture>

<br>

**Read before you run.** An offline reader for shell commands: it splits a
one-liner into the stages it is really made of, says in plain English what each
one does, draws the pipeline as a diagram, and names the risks — with a safer
way to do the same job. It never runs, simulates or fetches anything.

<br>

![Python](https://img.shields.io/badge/Python-3.10%2B-7A5D18?style=flat-square)
![PyQt6](https://img.shields.io/badge/UI-PyQt6-7A5D18?style=flat-square)
![Offline](https://img.shields.io/badge/network-never-2C6249?style=flat-square)
![Tests](https://img.shields.io/badge/tests-1103%20passing-2C6249?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-847D6E?style=flat-square)

</div>

---

## Why

Somebody says *"just paste this into your terminal"*, and the line they hand you
is one gesture long:

```bash
curl -fsSL https://example.com/install.sh | sudo bash
```

It is not one gesture. It is two programs joined by a pipe, the second of which
executes, as root, text that arrived from the internet a quarter of a second
ago and that nobody — not you, not the person who sent it — has read. The shell
flattens that into a single line, and the flattening is most of why people run
things they did not mean to.

Caveat unflattens it. Paste the line, and it shows you three things:

- **The pipeline** — every stage as its own box, left to right, with the
  operator between them labelled: what travels down the pipe, which half runs
  as root, which box is executing input nothing has read.
- **What each stage does** — a plain sentence per command, with the flags that
  change the answer. Not `-rf`, but *recurse into directories and never prompt*.
- **The risks** — each one a property of *your* line, with a short reason and a
  safer way to do the same job.

<div align="center">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="images/screens-dark.png">
  <img src="images/screens.png" alt="An install script read as RISKY, and a seven-stage log pipeline read as ROUTINE" width="100%">
</picture>
<br>
<sub>The install-script shape (RISKY), beside a seven-stage read-only pipeline (ROUTINE).</sub>
</div>

## The honest part

Caveat reads the **text** of a command and nothing else. It cannot know what
your aliases, shell functions or `PATH` will turn these words into, what a
remote script will contain at the moment it is fetched, or what the files on
your machine are worth to you. That last question is the only one that actually
decides whether a command is dangerous, and it is the one question a program
cannot answer.

So the verdict is four words, and the top one is deliberately modest:

| | |
|---|---|
| **ROUTINE** | Nothing matched. Every command was recognised, the line parsed cleanly. |
| **WORTH A LOOK** | A real hazard — *or* a gap in what Caveat could read. |
| **RISKY** | Code nobody has read is run, or a way in is opened, or root takes its orders from elsewhere. |
| **DESTRUCTIVE** | Something here removes data that does not come back. |

Three rules hold that line:

- **ROUTINE is not permission.** It means nothing in the register matched — not
  that the line is safe, not that it does what its sender says. The word
  *safe* never appears in a result, by design.
- **Unknown beats a guess.** A line containing one command Caveat has never
  heard of cannot be ROUTINE, because "nothing matched" would then mean
  "nothing was looked at". The same goes for a line whose quotes do not close,
  and for one whose first word is a variable. The headline says *why* it was
  capped. The same rule governs the flags: `-n` is a line count to `head` and a
  dry run to `rsync`, so a flag is explained only where its meaning is known
  for *that* command, and otherwise it is left unexplained. Silence is honest;
  a confident wrong gloss would not be.
- **Shapes, not names.** Every detection is a property of the text: a *fetcher*
  piped into something that *executes what it is given*; a delete target that
  is a variable with a slash glued on. There is no list of bad domains or
  forbidden tools, because such a list is out of date the day it ships and it
  teaches nothing.

And the obvious one, stated because it is the whole premise: **Caveat never
executes, simulates or fetches anything.** There is no flag that makes it. It
opens no sockets and resolves no names; the entire reading is the standard
library looking at text you already have.

## Install

```bash
git clone https://github.com/at0m-b0mb/Caveat.git
cd Caveat
python3 -m pip install -r requirements.txt   # just PyQt6, for the window
```

The engine and the command line need **no dependencies at all** — only the
standard library. PyQt6 is required solely for the graphical reader.

## Run

**The window:**

```bash
python3 -m caveat          # or:  python3 run.py
```

Paste a command, open a script, or load one of the bundled samples. Switch
between **Light**, **Dark** and **Auto** from the top-right.

**The command line** — same engine, no Qt, pipe-friendly:

```bash
caveat install.sh                                     # a readable report
caveat -e 'curl -fsSL https://x/i.sh | sudo bash'      # read a line directly
echo 'rm -rf $DIR/' | caveat -                         # from a pipe
caveat install.sh --json                               # machine-readable
python3 -m caveat install.sh                           # without installing
```

```
  RISKY   This line does something you should not run on trust

The pipeline
  1. curl
     download a URL, or send a request to one
    │  stdout
  2. bash  [ROOT · RUNS UNREAD INPUT]
     run shell commands

Findings (5: 2 good, 1 notice, 1 warning, 1 alert)
  [ alert ] Downloaded code is piped straight into a shell  stage 1,2
          curl fetches https://example.com/i.sh and `bash` runs it as root,
          line by line as it arrives…
          Instead: Split it in two. Fetch to a file, read the file, then run it.
```

Exit status is `0` for a successful reading and `2` when there was nothing to
read — Caveat does not signal the verdict through the exit code, because a
script that branches on it would be making exactly the judgement the tool
refuses to make for you.

## What it looks for

Twenty-seven rules, each one a shape rather than a name.

| Family | What trips it |
|---|---|
| **Running unread code** | a fetcher piped into a shell; `bash <(curl …)`; `eval "$(curl …)"`; text decoded from base64 or hex and then run |
| **Deleting** | `rm -rf` aimed at `/`, `~`, `$HOME`, a system directory, a glob, or a variable with a path glued on — the last of which becomes `rm -rf /` the moment the variable is empty |
| **Disks** | `dd of=/dev/…`, `mkfs`, `wipefs -a`, a redirect onto a block device, `shred` on a device |
| **The fork bomb** | a function that calls itself twice and backgrounds both |
| **Permissions** | `chmod 777`, the setuid bit, a recursive `chmod` across a system path, `chown -R` outside a home directory, `setenforce 0` |
| **Privilege** | every stage that runs as root, named; a pipe *into* `sudo`; `sudo -S` reading a password from the pipe |
| **Transport** | `curl -k`, `--no-check-certificate`, `http.sslVerify=false`, `--trusted-host`; plain `http://` — worse when what arrives is executed |
| **Trust** | `StrictHostKeyChecking=no`, `UserKnownHostsFile=/dev/null`, agent forwarding |
| **Backdoors** | `nc -e`, `bash -i >& /dev/tcp/…`, `socat … exec:`, an inline program that opens a socket and duplicates it onto the standard streams |
| **The record** | `history -c`, `unset HISTFILE`, deleting or truncating a log, `journalctl --vacuum-*` |
| **Persistence** | a crontab being installed or removed, `at`, `systemd-run`, `systemctl enable`, a trailing `&` |
| **Defences off** | `ufw disable`, `iptables -F`, a default policy of ACCEPT, `nft flush ruleset` |
| **Containers** | `--privileged`, the host root or the Docker socket mounted in, host networking |
| **Supply chain** | a package installed from a URL or a replacement index; npm install scripts; global installs |
| **Quoting** | an unquoted `$VAR` used as a path, an unquoted `$@` |
| **The unknown** | a command with no dictionary entry, a command word built from a variable, a program named by path, quoting that never closes, a program written inline in another language |

Findings are sorted most-severe first, and the serious ones always carry an
alternative — a warning with no way out only teaches people to click past
warnings.

## How it reads a line

```
  text  →  chunks  →  stages  →  sentences  →  findings  →  a verdict
```

The splitter is **tolerant**, not strict. It labels every run of the text once
— word, quoted run, substitution, redirection, operator — and after that
nothing has to think about quoting again. A stage that cannot be tokenised
cleanly says so and carries on, and the ceiling notices that it did.

It reads *into* the line as well as across it: a `$( … )` substitution, a
`<( … )` process substitution and a `-c` script handed to a shell are all
command lines in their own right, so they are read as stages too, down three
levels, with every finding attributed back to the box on the diagram you can
actually point at.

A few things it gets right that are easy to get wrong:

- `2>&1` keeps its ampersand instead of backgrounding the stage.
- `awk '{print $2}'` is not an unquoted variable; `rm -rf $DIR` is.
- `-fsSL` expands to four flags; `find -name` stays one option.
- `curl -c cookies.txt` is a cookie jar, not a script to be read.
- A here-document body is set aside and *said* to be set aside, rather than
  parsed as if it were commands.
- `( crontab -l; echo … ) | crontab -` is three stages, not a mystery word
  beginning with a bracket.

## Privacy

Caveat never touches the network. It opens no sockets, resolves no names, and
sends nothing anywhere. A command you paste in stays on your machine — which
matters, because the lines people most want explained are often the ones they
should not be forwarding to a web service.

## Tests

```bash
python3 -m pip install -r requirements-dev.txt
python3 -m pytest -q
```

1103 tests. Every rule has two: a line that must trip it, and a line that looks
like it but must not — the second being the one that keeps the tool usable. The
diagram's wrapping is tested with a stand-in text measurer so it can be
exercised at every width without a screen, and the palette is held to WCAG AA
on every text/background pairing in both themes.

## Layout

```
caveat/
  core/            the engine — pure standard library, no Qt
    model.py         the dataclasses everything speaks in
    lexer.py         text  ->  chunks  ->  stages, tolerantly
    explain.py       the dictionary: 187 commands and the flags that bite
    rules.py         27 detections, each with a safer alternative
    assess.py        the verdict, and the ceiling over it
  ui/              the window
    theme.py         the design system: one place for every token
    pipeline.py      the pipeline diagram — Caveat's signature element
    widgets.py       cards, chips, key/value rows
    main_window.py   the reader itself
  cli.py           the same engine on the command line
samples/           seven synthetic lines spanning the whole verdict range
tests/             1103 tests, including the contrast suite
tools/             screenshot capture and repository art
```

## Colophon

Set in **Iowan Old Style** for identity, the system **sans** for anything you
read, and a **mono** for the commands themselves — because a command *is* code,
and setting it in body text is the first small lie a tool like this can tell.
The palette is warm paper and two golds: a deep brass legible as small text,
and a brighter shine used only on marks that carry no words. Dark mode is true
black, with nothing in the ramp that reads as blue. Every colour is declared as
a light/dark pair, and a test suite holds every pairing to WCAG AA so the theme
cannot quietly regress.

## License

MIT — see [LICENSE](LICENSE). For authorised, educational and personal use:
Caveat is a reader, not a runner.
