"""
What each command is for, said once, in plain English.

This is a dictionary, not a judgement. Every entry gives a command a one-line
role — the sentence you would use to a colleague — a *family* the rules can
reason about structurally, and a short glossary for the flags that change what
the command does to your machine rather than merely how it prints.

Two deliberate limits:

* **The glossary is small on purpose.** It covers the flags that matter when
  somebody is about to paste a line they did not write. Explaining every option
  of ``tar`` would bury the one that overwrites absolute paths.
* **A command Caveat has never heard of is said to be unknown**, loudly, rather
  than guessed at. :mod:`caveat.core.assess` turns that into a ceiling, because
  "I do not know what this is" is a more useful answer than a confident wrong
  one.

Families, not names, are what the rules use: a rule asks "is this stage a
*fetcher* piped into a *shell*", so a tool nobody has thought of yet is handled
by adding one line here rather than by editing the rules.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .model import Explanation, Stage

# --- families ---------------------------------------------------------------
# The kinds a rule is allowed to ask about. Anything outside this list is
# "other", and the rules treat it as an unknown quantity.

FETCH = "fetch"            # brings bytes in from somewhere else
SHELL = "shell"            # executes whatever text it is given
INTERPRETER = "interp"     # executes a program in some other language
DESTROY = "destroy"        # removes or overwrites data
DISK = "disk"              # operates on a block device or a filesystem
PERMISSION = "perm"        # changes who may do what
ELEVATE = "elevate"        # changes who you are
PACKAGE = "package"        # installs software
CONTAINER = "container"
SERVICE = "service"
PROCESS = "process"
NETWORK = "network"
TEXT = "text"              # reads or rewrites a stream
INSPECT = "inspect"        # reports, changes nothing
ARCHIVE = "archive"
ENCODE = "encode"          # changes the representation of bytes
CRYPTO = "crypto"
SCHEDULE = "schedule"      # arranges for something to run later
VCS = "vcs"
FILES = "files"            # copies, moves, creates
HISTORY = "history"        # touches the record of what you did
BUILTIN = "builtin"

# Families whose members, by themselves, only report.
READ_ONLY = frozenset({INSPECT, TEXT})


@dataclass(frozen=True)
class CommandInfo:
    """One command: what it is for, what family it belongs to, which flags bite."""

    role: str
    kind: str = "other"
    flags: dict[str, str] = field(default_factory=dict)
    subcommands: dict[str, str] = field(default_factory=dict)


def _c(role: str, kind: str = "other", flags: dict[str, str] | None = None,
       subcommands: dict[str, str] | None = None) -> CommandInfo:
    return CommandInfo(role=role, kind=kind, flags=flags or {},
                       subcommands=subcommands or {})


# Flags that mean roughly the same thing wherever they appear. Consulted only
# after the command's own glossary, so a local meaning always wins.
GENERIC_FLAGS: dict[str, str] = {
    "-v": "verbose",
    "-q": "quiet",
    "-f": "force",
    "-r": "recursive",
    "-R": "recursive",
    "-y": "answer yes to everything",
    "-h": "human-readable",
    "-n": "dry run or no-clobber",
    "-i": "interactive",
    "-a": "all",
    "--force": "never stop to ask",
    "--yes": "answer yes to everything",
    "--quiet": "quiet",
    "--verbose": "verbose",
    "--recursive": "recursive",
    "--help": "print usage and exit",
    "--version": "print the version and exit",
}


COMMANDS: dict[str, CommandInfo] = {
    # --- bringing things in -------------------------------------------------
    "curl": _c("download a URL, or send a request to one", FETCH, {
        "-s": "silent",
        "-S": "still show errors while silent",
        "-L": "follow redirects wherever they lead",
        "-k": "accept ANY TLS certificate, valid or not",
        "--insecure": "accept ANY TLS certificate, valid or not",
        "-f": "fail quietly on an HTTP error",
        "-o": "write the body to a named file",
        "-O": "write the body to a file named after the URL",
        "-d": "send this data in the request body",
        "--data-binary": "send this data in the request body, unmodified",
        "-H": "add a request header",
        "-X": "use this HTTP method",
        "-u": "send these credentials",
        "-A": "claim this user agent",
        "-b": "send these cookies",
        "-c": "save cookies to this file",
        "--proxy": "route the request through a proxy",
        "--retry": "try again on failure",
        "-I": "fetch the headers only",
    }),
    "wget": _c("download a URL to a file", FETCH, {
        "-q": "quiet",
        "-O": "write to this file ('-' means standard output)",
        "-P": "save under this directory",
        "-c": "resume a partial download",
        "-r": "follow links and download recursively",
        "--mirror": "copy the whole site",
        "--no-check-certificate": "accept ANY TLS certificate, valid or not",
        "-i": "read the list of URLs from a file",
        "--post-data": "send this data in the request body",
    }),
    "aria2c": _c("download a URL with many connections at once", FETCH, {
        "--check-certificate": "whether to verify TLS at all",
    }),
    "ftp": _c("transfer files over FTP, a protocol with no encryption", FETCH),
    "scp": _c("copy files to or from another machine over SSH", NETWORK, {
        "-r": "copy directories recursively",
        "-i": "use this private key",
        "-P": "connect to this port",
    }),
    "rsync": _c("synchronise two directory trees, locally or over SSH", FILES, {
        "-a": "archive mode: recursive, keeping permissions and times",
        "-v": "verbose",
        "-z": "compress in transit",
        "--delete": "delete anything on the far side that is not on this one",
        "-e": "use this program as the transport",
        "-n": "dry run — show what would happen and change nothing",
    }),

    # --- things that execute what they are given ----------------------------
    "sh": _c("run shell commands", SHELL, {
        "-c": "run the next argument as a script",
        "-e": "stop at the first command that fails",
        "-x": "print each command before running it",
    }),
    "bash": _c("run shell commands", SHELL, {
        "-c": "run the next argument as a script",
        "-i": "behave like an interactive shell",
        "-e": "stop at the first command that fails",
        "-x": "print each command before running it",
        "-s": "read the script from standard input",
    }),
    "zsh": _c("run shell commands", SHELL, {
        "-c": "run the next argument as a script",
        "-s": "read the script from standard input",
    }),
    "dash": _c("run shell commands", SHELL, {"-c": "run the next argument as a script"}),
    "ksh": _c("run shell commands", SHELL, {"-c": "run the next argument as a script"}),
    "csh": _c("run shell commands", SHELL, {"-c": "run the next argument as a script"}),
    "tcsh": _c("run shell commands", SHELL, {"-c": "run the next argument as a script"}),
    "fish": _c("run shell commands", SHELL, {"-c": "run the next argument as a script"}),
    "ash": _c("run shell commands", SHELL, {"-c": "run the next argument as a script"}),
    "eval": _c("turn a string into commands and run them", SHELL),
    "source": _c("run a file's commands inside this shell, not a new one", SHELL),
    ".": _c("run a file's commands inside this shell, not a new one", SHELL),
    "exec": _c("replace this shell with another program", BUILTIN),
    "python": _c("run Python", INTERPRETER, {
        "-c": "run the next argument as a program",
        "-m": "run a module as a program",
        "-u": "do not buffer output",
    }),
    "python3": _c("run Python", INTERPRETER, {
        "-c": "run the next argument as a program",
        "-m": "run a module as a program",
        "-u": "do not buffer output",
    }),
    "perl": _c("run Perl", INTERPRETER, {
        "-e": "run the next argument as a program",
        "-i": "edit files in place",
        "-n": "loop over input lines",
    }),
    "ruby": _c("run Ruby", INTERPRETER, {"-e": "run the next argument as a program"}),
    "node": _c("run JavaScript", INTERPRETER, {"-e": "run the next argument as a program"}),
    "php": _c("run PHP", INTERPRETER, {"-r": "run the next argument as a program"}),
    "lua": _c("run Lua", INTERPRETER, {"-e": "run the next argument as a program"}),
    "osascript": _c("run AppleScript, which can drive other applications",
                    INTERPRETER, {"-e": "run the next argument as a script"}),
    "powershell": _c("run PowerShell", INTERPRETER, {
        "-Command": "run the next argument as a script",
        "-EncodedCommand": "run a base64-encoded script",
        "-ExecutionPolicy": "override the script-signing policy",
    }),
    "pwsh": _c("run PowerShell", INTERPRETER, {
        "-Command": "run the next argument as a script",
    }),

    # --- removing and overwriting -------------------------------------------
    "rm": _c("delete files and directories", DESTROY, {
        "-r": "recurse into directories",
        "-R": "recurse into directories",
        "--recursive": "recurse into directories",
        "-f": "never prompt, and say nothing about what is missing",
        "--force": "never prompt, and say nothing about what is missing",
        "-rf": "recurse into directories and never prompt",
        "-fr": "recurse into directories and never prompt",
        "-i": "ask before every file",
        "-d": "remove empty directories",
        "-v": "name each file as it goes",
        "--no-preserve-root": "allow '/' itself to be the target",
    }),
    "shred": _c("overwrite a file's bytes so it cannot be recovered", DESTROY, {
        "-u": "remove the file afterwards",
        "-z": "finish with a pass of zeroes",
        "-n": "how many overwrite passes",
        "-f": "change permissions if needed to write",
    }),
    "srm": _c("overwrite and delete a file so it cannot be recovered", DESTROY),
    "truncate": _c("set a file's length, discarding whatever is past it", DESTROY, {
        "-s": "the new size ('0' empties the file)",
    }),
    "dd": _c("copy blocks of bytes from one place to another, exactly as they are",
             DISK, {
        "if=": "the source — a file or a device",
        "of=": "the DESTINATION — a file or a device, written over in place",
        "bs=": "how many bytes per block",
        "count=": "how many blocks to copy",
        "status=": "how much progress to print",
    }),
    "mkfs": _c("create a new, empty filesystem on a device", DISK),
    "wipefs": _c("erase the filesystem signatures on a device", DISK, {
        "-a": "erase all of them",
    }),
    "fdisk": _c("edit a disk's partition table", DISK),
    "parted": _c("edit a disk's partition table", DISK),
    "diskutil": _c("inspect and alter macOS disks and volumes", DISK),
    "mount": _c("attach a filesystem into the directory tree", DISK),
    "umount": _c("detach a filesystem from the directory tree", DISK),

    # --- files and permissions ---------------------------------------------
    "cp": _c("copy files", FILES, {
        "-r": "copy directories recursively",
        "-a": "copy recursively, keeping permissions, times and links",
        "-f": "overwrite the destination without asking",
        "-n": "never overwrite an existing file",
        "-p": "keep the original permissions and times",
    }),
    "mv": _c("move or rename files", FILES, {
        "-f": "overwrite the destination without asking",
        "-n": "never overwrite an existing file",
    }),
    "ln": _c("make a link to a file", FILES, {
        "-s": "a symbolic link rather than a second name for the same data",
        "-f": "replace an existing link",
    }),
    "install": _c("copy a file into place and set its permissions in one step",
                  FILES, {"-m": "the permissions to give it"}),
    "mkdir": _c("create a directory", FILES, {"-p": "create parents as needed"}),
    "touch": _c("create an empty file, or update a file's timestamp", FILES),
    "chmod": _c("change what may be done to a file, and by whom", PERMISSION, {
        "-R": "apply to everything underneath, recursively",
        "--recursive": "apply to everything underneath, recursively",
        "-f": "say nothing about failures",
    }),
    "chown": _c("change which user and group owns a file", PERMISSION, {
        "-R": "apply to everything underneath, recursively",
        "-h": "change the link, not what it points at",
    }),
    "chgrp": _c("change which group owns a file", PERMISSION, {
        "-R": "apply to everything underneath, recursively",
    }),
    "chattr": _c("set low-level file attributes the owner cannot normally change",
                 PERMISSION, {"-i": "the immutable attribute"}),
    "setfacl": _c("set fine-grained access rules on a file", PERMISSION),
    "umask": _c("set the permissions new files will be created with", PERMISSION),
    "setenforce": _c("turn SELinux enforcement on or off", PERMISSION),

    # --- becoming someone else ---------------------------------------------
    "sudo": _c("run the rest of the line as another user, usually root", ELEVATE, {
        "-u": "run as this user instead of root",
        "-i": "start a login shell as that user",
        "-s": "start a shell as that user",
        "-E": "keep your current environment variables",
        "-S": "read the password from standard input instead of the terminal",
        "-n": "fail rather than ask for a password",
    }),
    "doas": _c("run the rest of the line as another user, usually root", ELEVATE),
    "su": _c("switch to another user's account", ELEVATE, {
        "-": "start a full login shell for that user",
        "-c": "run one command as that user",
    }),
    "pkexec": _c("run a program as another user through PolicyKit", ELEVATE),

    # --- installing software -----------------------------------------------
    "apt": _c("install and remove system packages", PACKAGE, {
        "-y": "answer yes to every prompt",
        "--allow-unauthenticated": "install packages whose signature does not check out",
        "--force-yes": "override every safety prompt at once",
    }, {"install": "add packages", "remove": "take packages away",
        "purge": "remove packages and their configuration",
        "update": "refresh the list of available packages",
        "upgrade": "install newer versions of what is already here"}),
    "apt-get": _c("install and remove system packages", PACKAGE, {
        "-y": "answer yes to every prompt",
        "--allow-unauthenticated": "install packages whose signature does not check out",
    }),
    "dpkg": _c("install a single Debian package file directly", PACKAGE, {
        "-i": "install this package file",
        "--force-all": "ignore every consistency check",
    }),
    "yum": _c("install and remove system packages", PACKAGE, {"-y": "answer yes"}),
    "dnf": _c("install and remove system packages", PACKAGE, {"-y": "answer yes"}),
    "rpm": _c("install a single RPM package file directly", PACKAGE, {
        "-i": "install", "--nodeps": "skip the dependency checks",
    }),
    "pacman": _c("install and remove system packages", PACKAGE, {
        "-S": "install", "--noconfirm": "answer yes to every prompt",
    }),
    "apk": _c("install and remove Alpine packages", PACKAGE),
    "snap": _c("install a self-contained package", PACKAGE, {
        "--classic": "drop the sandbox and give it the whole system",
    }),
    "brew": _c("install packages on macOS", PACKAGE, {
        "--force": "install over whatever is there",
    }, {"install": "add a package", "uninstall": "remove a package",
        "tap": "add a third-party source of formulae"}),
    "pip": _c("install Python packages", PACKAGE, {
        "-r": "install everything listed in this file",
        "--index-url": "fetch from this package index instead of the usual one",
        "--extra-index-url": "also fetch from this package index",
        "--trusted-host": "skip TLS verification for this host",
        "--break-system-packages": "install into the system's own Python",
        "-U": "upgrade what is already installed",
        "--user": "install for this user only",
    }, {"install": "add packages", "uninstall": "remove packages"}),
    "pip3": _c("install Python packages", PACKAGE, {
        "--trusted-host": "skip TLS verification for this host",
        "--break-system-packages": "install into the system's own Python",
    }),
    "npm": _c("install JavaScript packages", PACKAGE, {
        "-g": "install system-wide rather than into this project",
        "--unsafe-perm": "run package install scripts as root",
        "--ignore-scripts": "do NOT run the packages' own install scripts",
        "--strict-ssl": "whether to verify TLS at all",
    }, {"install": "add packages", "run": "run a script from package.json",
        "publish": "upload this package"}),
    "npx": _c("download a package and run it immediately", PACKAGE),
    "yarn": _c("install JavaScript packages", PACKAGE),
    "gem": _c("install Ruby packages", PACKAGE),
    "cargo": _c("build and install Rust packages", PACKAGE),
    "go": _c("build, run and install Go programs", PACKAGE),

    # --- containers and services -------------------------------------------
    "docker": _c("build and run containers", CONTAINER, {
        "--privileged": "give the container the host's own powers",
        "-v": "mount a host path inside the container",
        "--mount": "mount a host path inside the container",
        "--net": "put the container on this network",
        "--network": "put the container on this network",
        "-e": "set an environment variable inside it",
        "--rm": "delete the container when it exits",
        "-it": "attach a terminal to it",
    }, {"run": "start a new container", "exec": "run a command in a running one",
        "build": "build an image", "pull": "download an image",
        "system": "manage the daemon's own data"}),
    "podman": _c("build and run containers without a daemon", CONTAINER, {
        "--privileged": "give the container the host's own powers",
        "-v": "mount a host path inside the container",
    }),
    "kubectl": _c("control a Kubernetes cluster", CONTAINER, {
        "apply": "send this configuration to the cluster",
        "delete": "remove objects from the cluster",
    }),
    "systemctl": _c("start, stop and enable system services", SERVICE, {
        "--now": "take effect immediately as well as at boot",
        "-f": "force",
    }, {"start": "run it now", "stop": "stop it now",
        "enable": "make it start at boot", "disable": "stop it starting at boot",
        "mask": "make it impossible to start at all",
        "daemon-reload": "re-read the unit files"}),
    "service": _c("start or stop a system service", SERVICE),
    "launchctl": _c("load and unload macOS background jobs", SERVICE),
    "ufw": _c("configure the host firewall", NETWORK, {},
              {"disable": "turn the firewall off", "enable": "turn it on",
               "allow": "let traffic through"}),
    "iptables": _c("configure the Linux packet filter", NETWORK, {
        "-F": "flush — delete every rule in the chain",
        "-X": "delete the chain itself",
        "-P": "set the chain's default policy",
        "-A": "append a rule",
        "-j": "what to do with a matching packet",
    }),
    "nft": _c("configure the Linux packet filter", NETWORK, {
        "flush": "delete the rules",
    }),

    # --- processes ----------------------------------------------------------
    "kill": _c("send a signal to a process", PROCESS, {
        "-9": "SIGKILL — the process gets no chance to clean up",
        "-KILL": "SIGKILL — the process gets no chance to clean up",
        "-HUP": "hang-up: often a request to reload configuration",
        "-TERM": "ask the process to stop",
    }),
    "killall": _c("signal every process with a given name", PROCESS, {
        "-9": "SIGKILL — no chance to clean up",
    }),
    "pkill": _c("signal every process matching a pattern", PROCESS, {
        "-9": "SIGKILL — no chance to clean up",
        "-u": "only this user's processes",
        "-f": "match against the whole command line",
    }),
    "ps": _c("list the processes running now", INSPECT),
    "top": _c("watch processes as they run", INSPECT),
    "htop": _c("watch processes as they run", INSPECT),
    "nohup": _c("run something so it survives the terminal closing", PROCESS),
    "nice": _c("run something at a different scheduling priority", PROCESS),
    "timeout": _c("run something and stop it after a while", PROCESS),
    "watch": _c("run something again and again, showing the latest output", PROCESS),
    "sleep": _c("do nothing for a while", BUILTIN),
    "wait": _c("wait for background jobs to finish", BUILTIN),

    # --- networking ---------------------------------------------------------
    "ssh": _c("open a shell, or run one command, on another machine", NETWORK, {
        "-o": "set an SSH option by name",
        "-i": "authenticate with this private key",
        "-p": "connect to this port",
        "-L": "forward a local port to the far side",
        "-R": "forward a port on the far side back to here",
        "-D": "open a SOCKS proxy through the connection",
        "-N": "do not run a command, just hold the forwarding open",
        "-f": "go to the background once connected",
        "-t": "allocate a terminal on the far side",
        "-A": "forward your SSH agent to the far side",
    }),
    "sftp": _c("transfer files over SSH interactively", NETWORK),
    "nc": _c("open a raw network connection and move bytes down it", NETWORK, {
        "-e": "run this program and wire it to the connection",
        "-c": "run this command and wire it to the connection",
        "-l": "listen for an incoming connection instead of making one",
        "-p": "use this local port",
        "-k": "keep listening after a connection closes",
        "-z": "just test whether the port is open",
        "-n": "do not resolve names",
        "-u": "use UDP",
    }),
    "ncat": _c("open a raw network connection and move bytes down it", NETWORK, {
        "-e": "run this program and wire it to the connection",
        "-l": "listen for an incoming connection",
        "--ssl": "wrap the connection in TLS",
    }),
    "socat": _c("join any two byte streams together, including network and shell",
                NETWORK, {}),
    "telnet": _c("connect to a port with no encryption at all", NETWORK),
    "ping": _c("check whether a host answers", INSPECT),
    "dig": _c("look up DNS records", INSPECT),
    "nslookup": _c("look up DNS records", INSPECT),
    "host": _c("look up DNS records", INSPECT),
    "ifconfig": _c("show or set network interface settings", NETWORK),
    "ip": _c("show or set addresses, routes and links", NETWORK),
    "netstat": _c("list sockets and connections", INSPECT),
    "ss": _c("list sockets and connections", INSPECT),
    "arp": _c("show the table mapping IP addresses to hardware addresses", INSPECT),
    "route": _c("show or change the routing table", NETWORK),

    # --- text ---------------------------------------------------------------
    "cat": _c("print a file, or join several together", TEXT),
    "tac": _c("print a file backwards", TEXT),
    "echo": _c("print its arguments", TEXT),
    "printf": _c("print its arguments in a given format", TEXT),
    "grep": _c("print the lines that match a pattern", TEXT, {
        "-r": "search a whole directory tree",
        "-i": "ignore case",
        "-v": "print the lines that do NOT match",
        "-n": "show line numbers",
        "-E": "treat the pattern as an extended regular expression",
        "-o": "print only the matching part",
        "-l": "print only the names of matching files",
    }),
    "egrep": _c("print the lines that match an extended pattern", TEXT),
    "sed": _c("rewrite a stream of text by rule", TEXT, {
        "-i": "edit the FILES in place rather than printing the result",
        "-n": "print nothing unless asked to",
        "-e": "add another editing command",
        "-E": "use extended regular expressions",
    }),
    "awk": _c("pull fields out of each line, and compute with them", TEXT, {
        "-F": "the field separator",
        "-v": "set a variable for the program",
    }),
    "cut": _c("keep only some columns of each line", TEXT),
    "sort": _c("sort lines", TEXT),
    "uniq": _c("collapse repeated neighbouring lines", TEXT),
    "head": _c("print the first lines of a file", TEXT),
    "tail": _c("print the last lines of a file", TEXT, {
        "-f": "keep printing as the file grows",
    }),
    "tr": _c("replace or delete characters", TEXT),
    "wc": _c("count lines, words and bytes", TEXT),
    "tee": _c("pass a stream along and write a copy to a file", TEXT, {
        "-a": "append to the file rather than replacing it",
    }),
    "rev": _c("reverse each line", TEXT),
    "jq": _c("query and reshape JSON", TEXT),
    "xargs": _c("build a command line out of what it reads, then run it", SHELL, {
        "-I": "where to substitute each input item",
        "-0": "expect input separated by null bytes",
        "-n": "how many items per command",
        "-P": "how many to run at once",
        "-r": "do not run at all if the input is empty",
    }),
    "find": _c("walk a directory tree and act on what matches", FILES, {
        "-name": "match this filename pattern",
        "-type": "match this kind of entry",
        "-exec": "RUN this command on every match",
        "-execdir": "run this command on every match, from its own directory",
        "-delete": "DELETE every match",
        "-mtime": "match by modification age",
        "-user": "match by owner",
        "-perm": "match by permissions",
    }),

    # --- archives, encodings, crypto ---------------------------------------
    "tar": _c("pack files into an archive, or unpack one", ARCHIVE, {
        "-x": "extract",
        "-c": "create",
        "-t": "list the contents without extracting",
        "-z": "the archive is gzip-compressed",
        "-j": "the archive is bzip2-compressed",
        "-f": "the archive file to use",
        "-v": "name each file as it goes",
        "-C": "change to this directory first",
        "-P": "keep leading '/' in names, so files land at absolute paths",
        "--strip-components": "drop this many leading directories",
    }),
    "unzip": _c("unpack a zip archive", ARCHIVE, {
        "-o": "overwrite existing files without asking",
        "-d": "unpack into this directory",
    }),
    "zip": _c("pack files into a zip archive", ARCHIVE),
    "gzip": _c("compress a file in place", ARCHIVE, {"-d": "decompress instead"}),
    "gunzip": _c("decompress a gzip file", ARCHIVE),
    "bunzip2": _c("decompress a bzip2 file", ARCHIVE),
    "xz": _c("compress or decompress a file", ARCHIVE),
    "base64": _c("rewrite bytes as printable characters, or read them back",
                 ENCODE, {
        "-d": "DECODE back to the original bytes",
        "--decode": "DECODE back to the original bytes",
        "-w": "wrap the output at this width",
    }),
    "xxd": _c("show bytes as hexadecimal, or turn hexadecimal back into bytes",
              ENCODE, {"-r": "REVERSE: turn hexadecimal back into bytes",
                       "-p": "plain hex, no layout"}),
    "od": _c("print a file's bytes in a chosen notation", ENCODE),
    "uudecode": _c("turn uuencoded text back into bytes", ENCODE),
    "openssl": _c("the general-purpose cryptography toolkit", CRYPTO, {
        "-d": "DECRYPT rather than encrypt",
        "-k": "take the passphrase from the command line",
        "-pass": "where to read the passphrase from",
        "-in": "the input file",
        "-out": "the output file",
    }, {"enc": "encrypt or decrypt a file",
        "s_client": "open a TLS connection by hand",
        "req": "make a certificate request", "x509": "read a certificate"}),
    "gpg": _c("sign, verify, encrypt and decrypt with OpenPGP keys", CRYPTO, {
        "-d": "decrypt",
        "--verify": "check a signature",
        "--import": "add a key to your keyring",
    }),
    "md5sum": _c("print a file's MD5 digest", INSPECT),
    "sha256sum": _c("print a file's SHA-256 digest", INSPECT),
    "shasum": _c("print a file's digest", INSPECT),

    # --- the record of what you did ----------------------------------------
    "history": _c("show or alter this shell's record of your commands", HISTORY, {
        "-c": "CLEAR the history held in memory",
        "-w": "write the in-memory history over the history file",
        "-d": "delete one entry",
    }),
    "unset": _c("remove a shell variable", BUILTIN),
    "export": _c("put a variable into the environment of what runs next", BUILTIN),
    "alias": _c("give a command another name in this shell", BUILTIN),
    "set": _c("change how this shell behaves", BUILTIN),
    "trap": _c("run something when this shell receives a signal", BUILTIN),
    "journalctl": _c("read the systemd journal", INSPECT, {
        "--vacuum-time": "DELETE journal entries older than this",
        "--vacuum-size": "DELETE journal entries to get under this size",
        "--rotate": "start a new journal file",
    }),
    "logger": _c("write a line into the system log", INSPECT),

    # --- later, and elsewhere ----------------------------------------------
    "crontab": _c("install or read the table of commands run on a schedule",
                  SCHEDULE, {
        "-l": "list the current table",
        "-e": "edit the table",
        "-r": "REMOVE the whole table",
        "-u": "act on this user's table",
    }),
    "at": _c("arrange for a command to run once, later", SCHEDULE),
    "systemd-run": _c("start a command as a transient system unit", SCHEDULE),

    # --- version control ----------------------------------------------------
    "git": _c("work with a Git repository", VCS, {
        "-c": "set a configuration value for this one command",
        "--depth": "clone only this much history",
        "-f": "force",
    }, {"clone": "copy a repository", "pull": "fetch and merge",
        "push": "send commits to a remote", "checkout": "switch what is in the tree",
        "reset": "move the branch and possibly discard changes",
        "clean": "delete files Git is not tracking"}),
    "svn": _c("work with a Subversion repository", VCS),
    "hg": _c("work with a Mercurial repository", VCS),

    # --- looking around ----------------------------------------------------
    "ls": _c("list what is in a directory", INSPECT),
    "pwd": _c("print the directory you are in", INSPECT),
    "cd": _c("change the directory you are in", BUILTIN),
    "df": _c("show how full each filesystem is", INSPECT),
    "du": _c("show how much space files take up", INSPECT),
    "stat": _c("show a file's size, owner, permissions and times", INSPECT),
    "file": _c("guess what kind of data a file holds", INSPECT),
    "which": _c("show which program a name would run", INSPECT),
    "whereis": _c("show where a program lives", INSPECT),
    "type": _c("say whether a name is a program, a function or an alias", INSPECT),
    "whoami": _c("print the user you are running as", INSPECT),
    "id": _c("print your user and group identity", INSPECT),
    "uname": _c("print the kernel and machine name", INSPECT),
    "env": _c("print the environment, or run something with it changed", INSPECT),
    "uptime": _c("say how long the machine has been running", INSPECT),
    "date": _c("print or set the system clock", INSPECT),
    "lsof": _c("list the files and sockets processes have open", INSPECT),
    "defaults": _c("read and write macOS preference values", PERMISSION),
    "true": _c("do nothing, successfully", BUILTIN),
    "false": _c("do nothing, unsuccessfully", BUILTIN),
    "test": _c("compare things and report the answer as an exit status", BUILTIN),
    "read": _c("read a line into a shell variable", BUILTIN),
    "command": _c("run a program, ignoring any alias or function of that name",
                  BUILTIN),
    ":": _c("do nothing, successfully", BUILTIN),
}


# --- families as sets, for the rules ---------------------------------------

def _names_of(*kinds: str) -> frozenset[str]:
    return frozenset(name for name, info in COMMANDS.items()
                     if info.kind in kinds)


FETCHERS = _names_of(FETCH)
SHELLS = _names_of(SHELL)
INTERPRETERS = _names_of(INTERPRETER)
DECODERS = frozenset({"base64", "xxd", "uudecode", "od", "openssl", "gunzip",
                      "gzip", "bunzip2", "xz", "tr", "rev"})
READ_ONLY_COMMANDS = _names_of(INSPECT, TEXT) - {"tee", "sed"}


def info_for(command: str) -> CommandInfo | None:
    """The dictionary entry for a command, allowing for a few spellings."""
    if not command:
        return None
    name = command.rsplit("/", 1)[-1]
    if name in COMMANDS:
        return COMMANDS[name]
    # mkfs.ext4, mkfs.vfat, … are all the same command wearing a filesystem
    if name.startswith("mkfs"):
        return COMMANDS["mkfs"]
    if name.startswith("python3."):
        return COMMANDS["python3"]
    return None


def kind_of(command: str) -> str:
    info = info_for(command)
    return info.kind if info else "other"


def is_known(command: str) -> bool:
    return info_for(command) is not None


def runs_given_text(command: str) -> bool:
    """True for a command whose whole job is to execute what it is handed."""
    return kind_of(command) in (SHELL, INTERPRETER)


# --- turning a stage into a sentence ---------------------------------------

_CLUSTER = re.compile(r"^-[A-Za-z]{2,}$")


def gloss_flag(command: str, flag: str) -> list[tuple[str, str]]:
    """Explain one flag, splitting a cluster like ``-fsSL`` when it can.

    An exact entry always wins, so a single-dash long option (``-name``,
    ``-exec``) is never mistaken for a bag of letters. A cluster is only split
    when *every* letter in it has a meaning, which keeps the explanation honest
    rather than partial.
    """
    info = info_for(command)
    table = info.flags if info else {}

    def look(token: str) -> str:
        return table.get(token) or GENERIC_FLAGS.get(token, "")

    exact = look(flag)
    if exact:
        return [(flag, exact)]
    if _CLUSTER.match(flag):
        parts = [(f"-{ch}", look(f"-{ch}")) for ch in flag[1:]]
        if all(meaning for _, meaning in parts):
            return parts
    base = flag.split("=", 1)[0]
    if "=" in flag:
        meaning = look(base)
        if meaning:
            return [(base, meaning)]
    return []


def explain_stage(stage: Stage) -> Explanation:
    """One stage, said out loud."""
    info = info_for(stage.command)
    role = info.role if info else "Caveat has no entry for this command"
    exp = Explanation(index=stage.index, command=stage.command or "?",
                      role=role, kind=info.kind if info else "other",
                      known=info is not None, origin=stage.origin,
                      depth=stage.depth)

    seen: set[str] = set()
    for flag in stage.flags:
        for name, meaning in gloss_flag(stage.command, flag):
            if name in seen:
                continue
            seen.add(name)
            exp.flag_notes.append((name, meaning))

    if info and info.subcommands:
        for operand in stage.operands:
            if operand in info.subcommands:
                exp.extra.append(f"{operand} {info.subcommands[operand]}")
                break

    # `dd`'s arguments are key=value, not flags, so they arrive as operands
    if info:
        for operand in stage.operands:
            key = operand.split("=", 1)[0] + "="
            if key in info.flags and operand != key:
                exp.extra.append(f"{key} {info.flags[key]}")

    if stage.elevated and stage.command not in ("sudo", "su", "doas", "pkexec"):
        elevator = next((w for w in stage.wrappers if w in
                         ("sudo", "doas", "su", "pkexec")), "sudo")
        exp.extra.append(f"run through {elevator}, so as root")

    for redirect in stage.redirects:
        target = redirect.target
        if not target:
            continue
        if redirect.op == ">":
            exp.extra.append(f"output replaces {target}")
        elif redirect.op in (">>", "&>>"):
            exp.extra.append(f"output is appended to {target}")
        elif redirect.op == "<":
            exp.extra.append(f"input comes from {target}")
        elif redirect.op in (">&", "&>") and target.isdigit():
            streams = {"1": "stdout", "2": "stderr", "0": "stdin"}
            here = streams.get(redirect.fd or "1", f"stream {redirect.fd}")
            there = streams.get(target, f"stream {target}")
            exp.extra.append(f"{here} is merged into {there}")
        elif redirect.op in (">&", "&>"):
            exp.extra.append(f"both output streams go to {target}")

    return exp


CONNECTOR_WORDS = {
    "": "",
    "|": "stdout",
    "|&": "stdout + stderr",
    "&&": "if it succeeds",
    "||": "if it fails",
    ";": "then",
    "\n": "then",
}


def connector_phrase(connector: str) -> str:
    """What flows, or what decides, between two stages."""
    return CONNECTOR_WORDS.get(connector, connector)


def explain(script) -> list[Explanation]:
    """A sentence for every stage, nested ones included."""
    return [explain_stage(stage) for stage in script.walk()]
