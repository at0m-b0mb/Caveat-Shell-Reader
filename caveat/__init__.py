"""Caveat — read before you run.

An offline reader for shell commands: it splits a one-liner into the stages it
is really made of, says in plain English what each one does, draws the pipeline
as a diagram, and names the risks — without ever running, simulating or
fetching anything.
"""

from __future__ import annotations

__version__ = "1.0.1"
__all__ = ["__version__"]
