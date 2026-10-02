"""
The pipeline diagram — Caveat's signature.

A shell one-liner is a flow chart that has been flattened into a single line of
text, and the flattening is most of why people run things they did not mean to.
``curl … | sudo bash`` reads as one gesture; drawn as two boxes with an arrow
between them, labelled with what travels down it and which end runs as root, it
stops reading as one gesture at all.

So this widget unflattens it. One box per stage, left to right, wrapping like
text when it runs out of room: the command in mono, because it *is* code, its
plain-English role underneath, and the box tinted by the worst thing any rule
found on that stage. Between boxes, the connector — ``stdout`` for a pipe, *if
it succeeds* for ``&&`` — because the operator is the part that decides what
actually happens. A stage that runs as root carries a mark; a stage that
executes input it never read gets the alert treatment, which is the whole
picture the tool exists to show.

The arithmetic lives in :func:`layout_boxes`, which takes a text-measuring
function rather than asking Qt for one. That keeps the wrapping testable
without a screen — and wrapping is exactly the part that silently breaks.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from PyQt6.QtCore import QPointF, QRectF, QSize, Qt
from PyQt6.QtGui import (
    QBrush,
    QColor,
    QFont,
    QFontMetrics,
    QPainter,
    QPainterPath,
    QPen,
    QPolygonF,
)
from PyQt6.QtWidgets import QWidget

from ..core.explain import connector_phrase
from ..core.model import Severity, StageView
from . import theme

BOX_H = 86
BOX_MIN_W = 146
BOX_MAX_W = 244
BOX_PAD = 13
ARROW_W = 78
ROW_GAP = 40
MARGIN = 4

_SEV_TOKEN = {
    Severity.GOOD: "sev_good",
    Severity.INFO: "sev_info",
    Severity.NOTICE: "sev_notice",
    Severity.WARNING: "sev_warning",
    Severity.ALERT: "sev_alert",
}

Measure = Callable[[str, str], int]


@dataclass
class Box:
    """One stage, placed. Everything the painter needs and nothing else."""

    index: int
    x: float
    y: float
    w: float
    h: float
    title: str
    role: str
    severity: Severity = Severity.GOOD
    elevated: bool = False
    runs_unread: bool = False
    background: bool = False
    nested: bool = False
    connector: str = ""        # the label on the arrow arriving at this box
    wrapped: bool = False      # this box begins a new row
    row: int = 0


@dataclass
class Layout:
    """Where every box sits, and how tall the whole diagram came out."""

    boxes: list[Box] = field(default_factory=list)
    width: float = 0.0
    height: float = BOX_H + MARGIN * 2
    rows: int = 1


def marks_for(elevated: bool, runs_unread: bool, background: bool,
              nested: bool) -> list[tuple[str, str]]:
    """The pills a box wears, as (text, colour token).

    Shared by the layout and the painter so a box is never sized for fewer
    marks than it ends up drawing — which is how a label ends up underneath a
    badge in a window nobody resized during development.
    """
    marks: list[tuple[str, str]] = []
    if elevated:
        marks.append(("ROOT", "brass"))
    if runs_unread:
        marks.append(("UNREAD", "sev_alert"))
    if background:
        marks.append(("BG", "ink_faint"))
    if nested and not runs_unread:
        marks.append(("NESTED", "ink_muted"))
    return marks


def layout_boxes(views: Sequence[StageView], width: float,
                 measure: Measure) -> Layout:
    """Place one box per stage, wrapping when the row runs out.

    *measure* is given ``(text, type_role)`` and returns a pixel width, which
    is the only thing this function needs from the font system. A wrapped box
    is indented by one arrow width so the arrow arriving at it has somewhere to
    live, and the first box of a row records ``wrapped`` so the painter can
    draw the continuation marks rather than a straight arrow across the gap.
    """
    layout = Layout(width=width)
    if not views:
        return layout

    usable = max(BOX_MIN_W + MARGIN * 2, width) - MARGIN * 2
    x = float(MARGIN)
    y = float(MARGIN)
    row = 0

    for position, view in enumerate(views):
        title = view.title
        role = view.explanation.role
        marks = marks_for(view.elevated, view.runs_unread,
                          view.stage.background, bool(view.stage.inner))
        head = measure(f"STAGE {view.index + 1}", "label") + 12
        head += sum(measure(text, "label") + 14 for text, _ in marks)
        # the command is drawn two pixels larger than the mono token
        needed = max(measure(title, "mono") * 14 / 12,
                     measure(role, "small") * 0.55,
                     head)
        box_w = min(BOX_MAX_W, max(BOX_MIN_W, needed + BOX_PAD * 2))
        gap = 0.0 if position == 0 else ARROW_W
        wrapped = False

        if position and x + gap + box_w > MARGIN + usable:
            row += 1
            y += BOX_H + ROW_GAP
            x = MARGIN + ARROW_W
            wrapped = True
        else:
            x += gap

        layout.boxes.append(Box(
            index=view.index, x=x, y=y, w=box_w, h=BOX_H,
            title=title, role=role, severity=view.severity,
            elevated=view.elevated, runs_unread=view.runs_unread,
            background=view.stage.background,
            nested=bool(view.stage.inner),
            connector=connector_phrase(view.stage.connector),
            wrapped=wrapped, row=row))
        x += box_w

    layout.rows = row + 1
    layout.height = y + BOX_H + MARGIN
    return layout


class PipelineDiagram(QWidget):
    """The command line, drawn as the flow chart it already is."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._views: list[StageView] = []
        self._mode = theme.LIGHT
        self._layout = Layout()
        self.setMinimumHeight(BOX_H + MARGIN * 2)

    # --- data ---------------------------------------------------------------
    def set_data(self, views: Sequence[StageView], mode: str) -> None:
        self._views = list(views)
        self._mode = mode
        self._relayout()

    def _relayout(self) -> None:
        self._layout = layout_boxes(self._views, max(1, self.width()),
                                    self._measure)
        self.setMinimumHeight(int(self._layout.height))
        self.updateGeometry()
        self.update()

    def resizeEvent(self, event):  # noqa: N802  (Qt override)
        super().resizeEvent(event)
        self._relayout()

    def sizeHint(self) -> QSize:  # noqa: N802
        return QSize(560, int(self._layout.height))

    # --- painting -----------------------------------------------------------
    def paintEvent(self, event):  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        colour = lambda name: QColor(theme.color(name, self._mode))  # noqa: E731

        if not self._views:
            painter.setPen(colour("ink_faint"))
            painter.setFont(self._font("subtitle"))
            painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter,
                             "Nothing read yet.")
            painter.end()
            return

        boxes = self._layout.boxes
        for position, box in enumerate(boxes):
            if position:
                previous = boxes[position - 1]
                if box.wrapped:
                    self._draw_wrap(painter, previous, box, colour)
                else:
                    self._draw_arrow(painter, previous, box, colour)
            self._draw_box(painter, box, colour)
        painter.end()

    def _draw_box(self, painter: QPainter, box: Box, colour) -> None:
        token = _SEV_TOKEN[box.severity]
        accent = colour(token)
        alerting = box.runs_unread or box.severity is Severity.ALERT
        if box.severity is Severity.GOOD:
            fill = colour("surface")
        else:
            wash = token + "_wash"
            fill = colour(wash) if wash in theme.PALETTE else colour("surface_alt")

        rect = QRectF(box.x, box.y, box.w, box.h)
        painter.setPen(QPen(accent if alerting else colour("rule"),
                            2 if alerting else 1))
        painter.setBrush(QBrush(fill))
        painter.drawRoundedRect(rect.adjusted(0.5, 0.5, -0.5, -0.5), 6, 6)

        # the accent spine: which severity this stage speaks in
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QBrush(accent))
        spine = QPainterPath()
        spine.addRoundedRect(QRectF(box.x + 1, box.y + 1, 3.5, box.h - 2), 2, 2)
        painter.fillPath(spine, QBrush(accent))

        left = box.x + BOX_PAD
        inner_w = box.w - BOX_PAD * 2

        # the stage number, and the marks that change what the stage means
        painter.setPen(colour("ink_faint"))
        painter.setFont(self._font("label"))
        painter.drawText(QRectF(left, box.y + 8, inner_w * 0.4, 13),
                         Qt.AlignmentFlag.AlignVCenter
                         | Qt.AlignmentFlag.AlignLeft,
                         f"STAGE {box.index + 1}")

        marks = marks_for(box.elevated, box.runs_unread, box.background,
                          box.nested)
        mark_x = box.x + box.w - BOX_PAD
        metrics = QFontMetrics(self._font("label"))
        for text, mark_token in reversed(marks):
            text_w = metrics.horizontalAdvance(text) + 10
            pill = QRectF(mark_x - text_w, box.y + 6, text_w, 15)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QBrush(colour(mark_token)))
            painter.drawRoundedRect(pill, 3, 3)
            painter.setPen(colour("ink_inverse"))
            painter.setFont(self._font("label"))
            painter.drawText(pill, Qt.AlignmentFlag.AlignCenter, text)
            mark_x -= text_w + 4

        # the command itself, in mono, because it is code
        painter.setPen(colour("ink"))
        painter.setFont(self._font("mono", bold=True, size=14))
        painter.drawText(QRectF(left, box.y + 26, inner_w, 19),
                         Qt.AlignmentFlag.AlignVCenter
                         | Qt.AlignmentFlag.AlignLeft,
                         self._elide(box.title, inner_w, "mono", bold=True,
                                     size=14))

        # the role, in words, over at most two lines
        painter.setPen(colour("ink_muted"))
        painter.setFont(self._font("small"))
        for line_no, line in enumerate(self._fit(box.role, inner_w, "small", 2)):
            painter.drawText(QRectF(left, box.y + 48 + line_no * 15, inner_w, 15),
                             Qt.AlignmentFlag.AlignVCenter
                             | Qt.AlignmentFlag.AlignLeft, line)

    def _draw_arrow(self, painter: QPainter, previous: Box, box: Box,
                    colour) -> None:
        y = box.y + box.h / 2
        start = previous.x + previous.w + 7
        end = box.x - 7
        pen = QPen(colour("rule_strong"), 1.6)
        painter.setPen(pen)
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawLine(QPointF(start, y), QPointF(end - 5, y))
        self._arrowhead(painter, QPointF(end, y), colour("rule_strong"))

        if box.connector:
            painter.setPen(colour("brass"))
            painter.setFont(self._font("label"))
            painter.drawText(QRectF(start - 4, y - 19, end - start + 8, 14),
                             Qt.AlignmentFlag.AlignCenter,
                             self._elide(box.connector.upper(),
                                         end - start + 8, "label"))

    def _draw_wrap(self, painter: QPainter, previous: Box, box: Box,
                   colour) -> None:
        """The chain continues on the next row: a mark at each end of the break."""
        pen = QPen(colour("rule_strong"), 1.6)
        painter.setPen(pen)

        # leaving the end of the previous row
        out_x = previous.x + previous.w + 7
        out_y = previous.y + previous.h / 2
        painter.drawLine(QPointF(out_x, out_y), QPointF(out_x + 14, out_y))
        painter.drawLine(QPointF(out_x + 14, out_y),
                         QPointF(out_x + 14, out_y + 13))
        self._arrowhead(painter, QPointF(out_x + 14, out_y + 18),
                        colour("rule_strong"), down=True)

        # arriving at the start of this one
        in_y = box.y + box.h / 2
        in_x = box.x - 7
        gutter_x = box.x - ARROW_W + 12
        painter.setPen(pen)
        painter.drawLine(QPointF(gutter_x, in_y), QPointF(in_x - 5, in_y))
        self._arrowhead(painter, QPointF(in_x, in_y), colour("rule_strong"))

        if box.connector:
            painter.setPen(colour("brass"))
            painter.setFont(self._font("label"))
            painter.drawText(
                QRectF(gutter_x - 4, in_y - 22, ARROW_W, 14),
                Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                self._elide(box.connector.upper(), ARROW_W - 8, "label"))

    @staticmethod
    def _arrowhead(painter: QPainter, tip: QPointF, colour: QColor,
                   down: bool = False) -> None:
        size = 5.0
        if down:
            points = [tip, QPointF(tip.x() - size, tip.y() - size),
                      QPointF(tip.x() + size, tip.y() - size)]
        else:
            points = [tip, QPointF(tip.x() - size, tip.y() - size),
                      QPointF(tip.x() - size, tip.y() + size)]
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QBrush(colour))
        painter.drawPolygon(QPolygonF(points))

    # --- type ---------------------------------------------------------------
    def _font(self, role: str, bold: bool = False,
              size: int | None = None) -> QFont:
        family, default_size, weight = theme.TYPE[role]
        font = QFont()
        font.setFamilies([family.split(",")[0].strip().strip('"')])
        font.setPixelSize(size or default_size)
        heavy = bold or weight >= 600
        font.setWeight(QFont.Weight.DemiBold if heavy else QFont.Weight.Normal)
        return font

    def _measure(self, text: str, role: str) -> int:
        return QFontMetrics(self._font(role)).horizontalAdvance(text)

    def _elide(self, text: str, width: float, role: str, bold: bool = False,
               size: int | None = None) -> str:
        metrics = QFontMetrics(self._font(role, bold=bold, size=size))
        return metrics.elidedText(text, Qt.TextElideMode.ElideRight,
                                  max(10, int(width)))

    def _fit(self, text: str, width: float, role: str,
             max_lines: int) -> list[str]:
        """Break *text* into at most *max_lines*, eliding the last if needed."""
        metrics = QFontMetrics(self._font(role))
        limit = max(10, int(width))
        lines: list[str] = []
        current = ""
        for word in text.split():
            trial = f"{current} {word}".strip()
            if current and metrics.horizontalAdvance(trial) > limit:
                lines.append(current)
                current = word
                if len(lines) == max_lines:
                    break
            else:
                current = trial
        if len(lines) < max_lines and current:
            lines.append(current)
        if len(lines) == max_lines:
            consumed = len(" ".join(lines))
            if consumed < len(text):
                lines[-1] = metrics.elidedText(
                    text[max(0, consumed - len(lines[-1])):],
                    Qt.TextElideMode.ElideRight, limit)
        return lines[:max_lines]
