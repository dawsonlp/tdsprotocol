"""What the client shows: off, outline or full. It is rendered from the core's events and inspection trees.

off      nothing, and the core builds no inspection trees (the optimized mode)
outline  one line per step, message, TLS change, MARS frame and session change
full     the outline, plus each message's fields and bytes
"""

import enum
import sys
from typing import TextIO

from .connection.core import Event, Level  # Level is defined in the core because it decides what the core builds
from .wire import Node

PAGES = [  # the reference page that explains each definition, by its MS-TDS section (D-12). The first match is used.
    ("§2.2.3", "Packet"), ("§2.2.6.5", "PRELOGIN"), ("§2.2.6.4", "LOGIN7"),
    ("§2.2.5.3", "Requests"), ("§2.2.6.1", "Requests"), ("§2.2.6.6", "Requests"), ("§2.2.6.7", "Requests"),
    ("§2.2.6.9", "Requests"), ("§2.2.5", "Data Types"),
    ("§2.2.7.14", "Login Response"), ("§2.2.7.11", "Login Response"), ("§2.2.7.9", "Login Response"),
    ("§2.2.7.12", "Token Stream"), ("§2.2.7.22", "Token Stream"), ("§2.2.7", "Request Response"),
]


def page_of(source: str | None) -> str | None:
    """The reference page (docs/design/3-reference) that explains a definition with this MS-TDS section."""
    if source is None:
        return None
    return next((page for prefix, page in PAGES if source == prefix or source.startswith(prefix + ".")), None)


MARKS = {"step": "●", "tls": "⇄", "state": "≡", "channel": "◇", "pool": "▣", "send": " ", "receive": " ", "mars": " ", "encryption": "⚿"}
BYTES_SHOWN = 12


class Printer:
    """An observer for the core. Call it with each Event."""

    def __init__(self, level: Level, out: TextIO = sys.stderr, reveal_password: bool = False):
        """`reveal_password` shows the password at full level for the connections that this printer observes (D-12).
        The printer reverses LOGIN7's scrambling and shows the text. Otherwise every byte of the password is hidden."""
        self.level, self.out, self.reveal_password = level, out, reveal_password

    def __call__(self, event: Event) -> None:
        if self.level is Level.OFF:
            return
        indent = "" if event.kind == "step" else "  "
        took = f" · {event.took}" if event.took else ""
        print(f"{indent}{MARKS.get(event.kind, ' ')} {event.text}{took}", file=self.out)
        if self.level is Level.FULL and event.node is not None:
            for child in event.node.children:
                self._tree(child, depth=2)

    def _tree(self, node: Node, depth: int) -> None:
        pad = "    " * depth
        if node.children:
            page = page_of(node.source)
            print(f"{pad}{node.name}{'  · ' + node.shown if node.shown else ''}{f'   ⟶ {page}' if page else ''}",
                  file=self.out)
            for child in node.children:
                self._tree(child, depth + 1)
            return
        raw = node.raw[:BYTES_SHOWN]
        hidden = node.sensitive and not self.reveal_password
        shown = "•• " * len(raw) if hidden else raw.hex(" ").upper()
        more = " …" if len(node.raw) > BYTES_SHOWN else ""
        meaning = node.shown
        if node.sensitive and self.reveal_password and node.name in ("password", "new password"):
            from .login7 import unscramble
            meaning = f"“{unscramble(node.raw).decode('utf-16-le', 'replace')}” (revealed)"
        print(f"{pad}{node.name:<26} {shown + more:<40} {meaning}", file=self.out)
