#!/usr/bin/env python3
"""
Render the window off-screen and save PNGs — proof the interface works, and the
source of the README's contact sheet.

Runs headless (``QT_QPA_PLATFORM=offscreen``), so it needs no display. It grabs
each sample in both themes, writing ``images/shot-<sample>-<mode>.png``.
"""

from __future__ import annotations

import os
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from PyQt6.QtWidgets import QApplication  # noqa: E402

from caveat.ui import theme  # noqa: E402
from caveat.ui.main_window import MainWindow  # noqa: E402

SIZE = (1200, 880)
SHOTS = [
    ("install-script.sh", theme.LIGHT),
    ("install-script.sh", theme.DARK),
    ("wipe-the-disk.sh", theme.LIGHT),
    ("wipe-the-disk.sh", theme.DARK),
    ("benign-pipeline.sh", theme.LIGHT),
    ("benign-pipeline.sh", theme.DARK),
    ("obfuscated-payload.sh", theme.LIGHT),
    ("permissions-fix.sh", theme.LIGHT),
    ("log-triage.sh", theme.LIGHT),
    ("log-triage.sh", theme.DARK),
]


def main() -> int:
    app = QApplication.instance() or QApplication(sys.argv)
    out_dir = os.path.join(ROOT, "images")
    os.makedirs(out_dir, exist_ok=True)
    samples = os.path.join(ROOT, "samples")

    for name, mode in SHOTS:
        window = MainWindow(mode=mode)
        window.resize(*SIZE)
        with open(os.path.join(samples, name), encoding="utf-8") as handle:
            window.source.setPlainText(handle.read())
        window._on_read()
        window.show()
        app.processEvents()
        app.processEvents()
        path = os.path.join(out_dir, f"shot-{name[:-3]}-{mode}.png")
        window.grab().save(path)
        print(f"wrote {os.path.relpath(path, ROOT)}  ({mode})")
        window.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
