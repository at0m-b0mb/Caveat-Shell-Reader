"""
The diagram's arithmetic.

The layout is tested with a stand-in text measurer rather than a real font, so
the wrapping can be exercised at every width without a screen — and wrapping is
precisely the part that breaks silently, in a window nobody resized before
shipping.
"""

import pytest

pytest.importorskip("PyQt6")

from caveat.core.assess import read_command  # noqa: E402
from caveat.core.model import Severity  # noqa: E402
from caveat.ui.pipeline import (  # noqa: E402
    ARROW_W,
    BOX_H,
    BOX_MAX_W,
    BOX_MIN_W,
    MARGIN,
    ROW_GAP,
    layout_boxes,
    marks_for,
)


def measure(text, role):
    """A stand-in for a font: six pixels a character, which is close enough."""
    return len(text) * 6


def lay(source, width=900):
    return layout_boxes(read_command(source).views, width, measure)


# --- the basics -------------------------------------------------------------

def test_there_is_one_box_per_stage():
    assert len(lay("a | b | c").boxes) == 3


def test_no_views_means_no_boxes():
    assert layout_boxes([], 800, measure).boxes == []


def test_an_empty_layout_still_has_a_height():
    assert layout_boxes([], 800, measure).height >= BOX_H


def test_boxes_keep_their_stage_numbers():
    assert [b.index for b in lay("a | b | c").boxes] == [0, 1, 2]


def test_a_box_carries_the_command_and_its_role():
    box = lay("curl -sL https://x -o f").boxes[0]
    assert box.title == "curl" and "download" in box.role


# --- sizing -----------------------------------------------------------------

@pytest.mark.parametrize("source", ["ls", "systemctl", "a | b"])
def test_no_box_is_narrower_than_the_minimum(source):
    assert all(b.w >= BOX_MIN_W for b in lay(source).boxes)


def test_no_box_is_wider_than_the_maximum():
    boxes = lay("docker run --privileged -v /:/host alpine sh").boxes
    assert all(b.w <= BOX_MAX_W for b in boxes)


def test_a_box_with_marks_is_wide_enough_for_them():
    box = lay("curl -s https://x | sudo bash").boxes[1]
    marks = marks_for(box.elevated, box.runs_unread, box.background, box.nested)
    needed = measure("STAGE 2", "label") + 12
    needed += sum(measure(text, "label") + 14 for text, _ in marks)
    assert box.w >= needed


def test_every_box_on_a_row_shares_its_height():
    assert {b.h for b in lay("a | b | c").boxes} == {BOX_H}


# --- wrapping ---------------------------------------------------------------

def test_a_short_pipeline_stays_on_one_row():
    layout = lay("a | b", width=1200)
    assert layout.rows == 1
    assert all(not b.wrapped for b in layout.boxes)


def test_a_long_pipeline_wraps():
    layout = lay("a | b | c | d | e | f | g | h", width=600)
    assert layout.rows > 1
    assert any(b.wrapped for b in layout.boxes)


def test_the_first_box_never_counts_as_wrapped():
    assert lay("a | b | c | d | e | f", width=320).boxes[0].wrapped is False


def test_a_wrapped_box_is_indented_for_its_arrow():
    layout = lay("a | b | c | d | e | f | g", width=600)
    wrapped = [b for b in layout.boxes if b.wrapped]
    assert wrapped and all(b.x >= MARGIN + ARROW_W for b in wrapped)


def test_no_box_runs_off_the_right_edge():
    for width in (320, 480, 600, 820, 1100, 1600):
        layout = lay("a | b | c | d | e | f | g | h | i", width=width)
        limit = max(width, BOX_MIN_W + MARGIN * 2) + 1
        assert all(box.x + box.w <= limit for box in layout.boxes), width


def test_boxes_on_the_same_row_do_not_overlap():
    layout = lay("a | b | c | d | e | f | g | h", width=700)
    for row in {b.row for b in layout.boxes}:
        on_row = sorted((b for b in layout.boxes if b.row == row),
                        key=lambda b: b.x)
        for left, right in zip(on_row, on_row[1:]):
            assert left.x + left.w <= right.x


def test_consecutive_rows_are_separated_by_the_row_gap():
    layout = lay("a | b | c | d | e | f | g", width=600)
    tops = sorted({b.y for b in layout.boxes})
    for upper, lower in zip(tops, tops[1:]):
        assert lower - upper == BOX_H + ROW_GAP


def test_the_height_covers_every_row():
    layout = lay("a | b | c | d | e | f | g | h", width=500)
    assert layout.height >= max(b.y + b.h for b in layout.boxes)


def test_a_narrow_width_still_lays_out_one_box_per_row():
    layout = lay("a | b | c", width=10)
    assert layout.rows == 3


# --- what the boxes say -----------------------------------------------------

def test_the_connector_label_is_carried_on_the_arriving_box():
    boxes = lay("a | b && c").boxes
    assert boxes[1].connector == "stdout"
    assert boxes[2].connector == "if it succeeds"


def test_the_first_box_has_no_connector():
    assert lay("a | b").boxes[0].connector == ""


def test_an_elevated_stage_is_marked_root():
    box = lay("sudo rm -rf /tmp/x").boxes[0]
    assert box.elevated is True
    assert ("ROOT", "brass") in marks_for(True, False, False, False)


def test_a_stage_running_unread_input_gets_the_alert_treatment():
    box = lay("curl -s https://x | sh").boxes[1]
    assert box.runs_unread is True
    assert box.severity is Severity.ALERT


def test_a_backgrounded_stage_is_marked():
    assert lay("sleep 60 &").boxes[0].background is True


def test_a_stage_with_nested_commands_is_marked():
    assert lay("bash -c 'echo hi'").boxes[0].nested is True


def test_marks_are_ordered_most_important_first():
    marks = [text for text, _ in marks_for(True, True, True, True)]
    assert marks[:2] == ["ROOT", "UNREAD"]


def test_nested_is_not_shown_when_unread_already_is():
    marks = [text for text, _ in marks_for(False, True, False, True)]
    assert "NESTED" not in marks


def test_a_quiet_stage_wears_no_marks():
    assert marks_for(False, False, False, False) == []


def test_every_box_takes_its_tint_from_its_view():
    reading = read_command("curl -fsSL https://x/i.sh | sudo bash")
    layout = layout_boxes(reading.views, 900, measure)
    assert [b.severity for b in layout.boxes] == \
        [v.severity for v in reading.views]
