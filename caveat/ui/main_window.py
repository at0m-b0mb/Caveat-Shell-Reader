"""
The window.

Left: the command, pasted, opened from a file, or loaded from a sample. Right:
the reading — the verdict and what it cannot tell you, the pipeline drawn as a
diagram, a sentence for every stage, and every finding with a safer way to do
the same job. The window holds the current reading and rebuilds the whole right
side on a theme change, so the chips and the painted diagram always match the
active palette.

Nothing in here can run the command. The only thing the window does with the
text is read it.
"""

from __future__ import annotations

import os

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QAction
from PyQt6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMenu,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

from ..core.assess import read_command
from ..core.model import Reading, Severity, Verdict
from . import theme
from .pipeline import PipelineDiagram
from .widgets import Card, Chip, hrule, key_value, label, mini_label

_SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "samples")

_SEV_TOKEN = {
    Severity.GOOD: "sev_good",
    Severity.INFO: "sev_info",
    Severity.NOTICE: "sev_notice",
    Severity.WARNING: "sev_warning",
    Severity.ALERT: "sev_alert",
}

_VERDICT_TOKEN = {
    Verdict.ROUTINE: "sev_good",
    Verdict.WORTH_A_LOOK: "sev_notice",
    Verdict.RISKY: "sev_warning",
    Verdict.DESTRUCTIVE: "sev_alert",
}

_PLACEHOLDER = (
    "Caveat splits a shell command into the stages it is really made of, says "
    "what each one does in plain English, draws the pipeline, and names the "
    "risks — with a safer way to do the same job. It reads the text and "
    "nothing else: it never runs, simulates or fetches anything, and it never "
    "calls a command safe."
)

_PASTE_HINT = (
    "Paste the line somebody told you to run. Caveat reads it; it cannot run "
    "it, and there is no button here that would."
)


class MainWindow(QWidget):
    def __init__(self, mode: str = theme.AUTO):
        super().__init__()
        self._mode_choice = mode
        self._mode = theme.resolve(mode)
        self._reading: Reading | None = None

        self.setWindowTitle("Caveat")
        self.resize(1180, 790)
        self._build()
        self._apply_theme()

    # --- construction -------------------------------------------------------
    def _build(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        root.addWidget(self._build_header())

        split = QSplitter(Qt.Orientation.Horizontal)
        split.addWidget(self._build_source_pane())
        split.addWidget(self._build_report_pane())
        split.setStretchFactor(0, 4)
        split.setStretchFactor(1, 6)
        split.setSizes([430, 700])

        host = QWidget()
        host.setObjectName("PageHost")
        host_lay = QVBoxLayout(host)
        host_lay.setContentsMargins(16, 12, 16, 16)
        host_lay.addWidget(split)
        root.addWidget(host, 1)

    def _build_header(self) -> QWidget:
        bar = QWidget()
        bar.setObjectName("Rail")
        lay = QHBoxLayout(bar)
        lay.setContentsMargins(20, 12, 20, 12)

        mark = QLabel("CAVEAT")
        mark.setObjectName("Wordmark")
        sub = QLabel("read before you run")
        sub.setObjectName("WordmarkSub")
        wordmark = QVBoxLayout()
        wordmark.setSpacing(0)
        wordmark.addWidget(mark)
        wordmark.addWidget(sub)
        lay.addLayout(wordmark)
        lay.addStretch(1)

        lay.addWidget(mini_label("THEME"))
        self.theme_box = QComboBox()
        self.theme_box.addItems(["Auto", "Light", "Dark"])
        self.theme_box.setCurrentText(self._mode_choice.capitalize())
        self.theme_box.setFixedWidth(110)
        self.theme_box.currentTextChanged.connect(self._on_theme_changed)
        lay.addWidget(self.theme_box)
        return bar

    def _build_source_pane(self) -> QWidget:
        pane = QWidget()
        lay = QVBoxLayout(pane)
        lay.setContentsMargins(0, 0, 8, 0)
        lay.setSpacing(theme.SPACE["base"])

        lay.addWidget(label("Paste the command", "PageTitle"))
        lay.addWidget(label(_PASTE_HINT, "PageIntro"))

        self.source = QPlainTextEdit()
        self.source.setObjectName("Mono")
        self.source.setPlaceholderText(
            "curl -fsSL https://example.com/install.sh | sudo bash")
        lay.addWidget(self.source, 1)

        row = QHBoxLayout()
        read_btn = QPushButton("Read it")
        read_btn.setObjectName("Primary")
        read_btn.clicked.connect(self._on_read)
        row.addWidget(read_btn)

        open_btn = QPushButton("Open file…")
        open_btn.clicked.connect(self._on_open)
        row.addWidget(open_btn)

        self.sample_btn = QPushButton("Load sample")
        self._build_sample_menu()
        row.addWidget(self.sample_btn)

        clear_btn = QPushButton("Clear")
        clear_btn.setObjectName("Quiet")
        clear_btn.clicked.connect(self._on_clear)
        row.addWidget(clear_btn)
        row.addStretch(1)
        lay.addLayout(row)
        return pane

    def _build_sample_menu(self) -> None:
        menu = QMenu(self)
        try:
            names = sorted(f for f in os.listdir(_SAMPLES_DIR)
                           if f.endswith(".sh"))
        except OSError:
            names = []
        if not names:
            action = QAction("(no samples found)", self)
            action.setEnabled(False)
            menu.addAction(action)
        for name in names:
            pretty = name[:-3].replace("-", " ").capitalize()
            action = QAction(pretty, self)
            action.triggered.connect(lambda _=False, n=name: self._load_sample(n))
            menu.addAction(action)
        self.sample_btn.setMenu(menu)

    def _build_report_pane(self) -> QWidget:
        self.report_scroll = QScrollArea()
        self.report_scroll.setWidgetResizable(True)
        self._set_placeholder()
        return self.report_scroll

    # --- behaviour ----------------------------------------------------------
    def _on_theme_changed(self, text: str) -> None:
        self._mode_choice = text.lower()
        self._mode = theme.resolve(self._mode_choice)
        self._apply_theme()
        if self._reading is not None:
            self._render(self._reading)
        else:
            self._set_placeholder()

    def _apply_theme(self) -> None:
        self.setStyleSheet(theme.stylesheet(self._mode))

    def _on_read(self) -> None:
        source = self.source.toPlainText()
        if not source.strip():
            self._set_placeholder("Paste a command, or load a sample, to begin.")
            return
        self._reading = read_command(source)
        self._render(self._reading)

    def _on_open(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Open a script or a saved command", "",
            "Shell scripts (*.sh *.bash *.zsh *.txt);;All files (*)")
        if not path:
            return
        try:
            with open(path, encoding="utf-8", errors="replace") as handle:
                self.source.setPlainText(handle.read())
        except OSError as exc:
            self._set_placeholder(f"Could not open the file: {exc}")
            return
        self._on_read()

    def _load_sample(self, name: str) -> None:
        try:
            with open(os.path.join(_SAMPLES_DIR, name), encoding="utf-8") as fh:
                self.source.setPlainText(fh.read())
        except OSError as exc:
            self._set_placeholder(f"Could not load the sample: {exc}")
            return
        self._on_read()

    def _on_clear(self) -> None:
        self.source.clear()
        self._reading = None
        self._set_placeholder()

    # --- the report ---------------------------------------------------------
    def _set_placeholder(self, text: str = "") -> None:
        host = QWidget()
        lay = QVBoxLayout(host)
        lay.setContentsMargins(24, 24, 24, 24)
        lay.addStretch(1)
        lay.addWidget(label("Nothing read yet", "Figure"))
        lay.addWidget(label(text or _PLACEHOLDER, "PageIntro"))
        lay.addStretch(2)
        self.report_scroll.setWidget(host)

    def _render(self, reading: Reading) -> None:
        host = QWidget()
        lay = QVBoxLayout(host)
        lay.setContentsMargins(8, 4, 8, 16)
        lay.setSpacing(theme.SPACE["base"])

        lay.addWidget(self._verdict_card(reading))
        lay.addWidget(self._pipeline_card(reading))
        lay.addWidget(self._stages_card(reading))
        lay.addWidget(self._findings_card(reading))

        notes = list(reading.script.notes) + [
            f"Stage {stage.root + 1}: {note}"
            for stage in reading.script.walk() for note in stage.notes]
        if notes:
            card = Card("Notes on the reading itself", flat=True)
            for note in notes:
                card.add(label(note, muted=True))
            lay.addWidget(card)

        lay.addStretch(1)
        self.report_scroll.setWidget(host)

    def _verdict_card(self, reading: Reading) -> QWidget:
        card = Card()
        token = _VERDICT_TOKEN[reading.verdict]

        word = QLabel(reading.verdict.label)
        word.setWordWrap(True)
        word.setStyleSheet(
            f"{theme.font_css('display')} "
            f"color: {theme.color(token, self._mode)};")
        card.add(word)

        counts = reading.counts()
        tally = "  ·  ".join(f"{counts[s.value]} {s.value}"
                             for s in Severity if counts[s.value])
        card.add(mini_label(f"VERDICT  ·  {tally}" if tally else "VERDICT"))
        card.add(label(reading.headline, "PageTitle"))
        card.add(hrule())
        card.add(label(reading.ceiling_note, "Faint"))
        return card

    def _pipeline_card(self, reading: Reading) -> QWidget:
        stages = len(reading.views)
        card = Card("The pipeline")
        card.add(label(
            f"{stages} stage{'' if stages == 1 else 's'}. Each box is one "
            f"command; the label on an arrow is what passes between them. A "
            f"box tinted red runs input nothing has read, and ROOT marks a "
            f"stage that runs with no permission checks left.", "Faint"))
        diagram = PipelineDiagram()
        diagram.set_data(reading.views, self._mode)
        card.add(diagram)
        return card

    def _stages_card(self, reading: Reading) -> QWidget:
        card = Card("What each stage does")
        for explanation in reading.explanations:
            row = QWidget()
            lay = QHBoxLayout(row)
            lay.setContentsMargins(explanation.depth * 20, 0, 0, 0)
            lay.setSpacing(theme.SPACE["snug"])

            text = explanation.sentence
            if explanation.origin:
                text = f"{explanation.origin} — {text}"
            body = label(text, muted=not explanation.known)
            if not explanation.known:
                body.setStyleSheet(
                    f"color: {theme.color('sev_info', self._mode)};")
            lay.addWidget(body, 1)
            card.add(row)
        return card

    def _findings_card(self, reading: Reading) -> QWidget:
        card = Card(f"Findings ({len(reading.findings)})")
        if not reading.findings:
            card.add(label(
                "No rule matched. That is an absence, not a clearance.",
                muted=True))
            return card

        for position, finding in enumerate(reading.findings):
            if position:
                card.add(hrule())
            row = QHBoxLayout()
            row.setSpacing(theme.SPACE["base"])
            chip = Chip(finding.severity.value, _SEV_TOKEN[finding.severity],
                        self._mode)
            chip.setFixedWidth(84)
            row.addWidget(chip, 0, Qt.AlignmentFlag.AlignTop)

            column = QVBoxLayout()
            column.setSpacing(3)
            head = QHBoxLayout()
            head.addWidget(label(finding.title, "body"), 1)
            if finding.stages:
                head.addWidget(label(
                    "stage " + ", ".join(str(i + 1) for i in finding.stages),
                    "Faint"), 0, Qt.AlignmentFlag.AlignTop)
            column.addLayout(head)
            column.addWidget(label(finding.detail, muted=True))
            if finding.safer:
                safer = label(f"Instead: {finding.safer}", "Faint")
                safer.setStyleSheet(
                    f"{theme.font_css('small')} "
                    f"color: {theme.color('brass', self._mode)};")
                column.addWidget(safer)
            row.addLayout(column, 1)
            card.add_layout(row)
        return card
