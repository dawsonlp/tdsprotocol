# /// script
# requires-python = ">=3.14"
# dependencies = ["markdown-it-py>=4,<5"]
# ///
"""Render the Rust plan and its baseline into the offline design site.

Run: uv run tools/render_planning_pages.py
The Markdown files remain the system of record. Generated pages need no runtime
Markdown library or build step. Existing hand-authored site pages are untouched.
"""

import json
import re
from pathlib import Path

from markdown_it import MarkdownIt

ROOT = Path(__file__).resolve().parents[1]
PAGES = (
    ("D-rust-development.md", "rust", "D", "Building the Rust Client", "explanation"),
    ("E-python-baseline.md", "python-baseline", "E", "Python Baseline", "check"),
)
ROUTES = {
    "C-roadmap.md": "roadmap",
    "5-done-when.md": "done-when",
    **{source: route for source, route, *_ in PAGES},
}


def render() -> None:
    markdown = MarkdownIt("commonmark").enable("table")
    for source, route, number, title, kind in PAGES:
        lines = (ROOT / "docs/design" / source).read_text().splitlines()
        where = next(line.removeprefix("**Where this sits:** ") for line in lines if line.startswith("**Where this sits:**"))
        outcome = next(line.removeprefix("**After reading this you can** ") for line in lines if line.startswith("**After reading this you can**"))
        body = "\n".join(line for line in lines if not line.startswith(("# ", "**Where this sits:**", "**After reading this you can**")))

        def site_html(text: str, *, inline: bool = False) -> str:
            tokens = markdown.parseInline(text) if inline else markdown.parse(text)
            for token in tokens:
                for child in token.children or []:
                    if child.type != "link_open":
                        continue
                    href = child.attrGet("href") or ""
                    target, separator, anchor = href.partition("#")
                    if target in ROUTES:
                        child.attrSet("href", "#/" + ROUTES[target] + ("/" + anchor if separator else ""))
                    elif href.startswith("#"):
                        child.attrSet("href", "#/" + route + "/" + anchor)
            return markdown.renderer.render(tokens, markdown.options, {})

        def heading(match: re.Match) -> str:
            tag, content = match.groups()
            text = re.sub(r"<[^>]+>", "", content).lower()
            anchor = re.sub(r"[^a-z0-9_]+", "-", text).strip("-")
            return f'<{tag} id="{anchor}">{content}</{tag}>'

        html = site_html(body)
        html = re.sub(r"<(h[23])>(.*?)</\1>", heading, html)
        html = html.replace('<table>', '<div class="tbl-wrap"><table class="tbl">')
        html = html.replace('</table>', '</table></div>')
        html = html.replace('<pre>', '<figure class="code"><pre>')
        html = html.replace('</pre>', '</pre></figure>')
        metadata = dict(id=route, group="Design", num=number, kind=kind, title=title,
                        where=site_html(where, inline=True), outcome=site_html(outcome, inline=True))
        # JSON encoding keeps backticks, dollar signs and quotes literal in JavaScript.
        output = (f"/* Generated from docs/design/{source} by tools/render_planning_pages.py. */\n"
                  "(function () {\n  const page = " + json.dumps(metadata, ensure_ascii=False, indent=2) + ";\n"
                  "  page.body = () => [\n" + "\n".join(
                      "    " + json.dumps(line, ensure_ascii=False) + "," for line in html.splitlines()
                  ) + "\n  ].join('\\n');\n"
                  "  window.TDS.page(page);\n})();\n")
        (ROOT / "site/pages" / f"{route}.js").write_text(output)


if __name__ == "__main__":
    render()
