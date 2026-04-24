"""Server-side YAML syntax highlighting via Pygments.

Pure function — takes a YAML string, returns HTML with ``highlight``-class
spans that our CSS colorizes against the palette. Used by the preview pane
when rendering the canonical rule YAML.

Kept in ``web/`` because it's a presentation concern; ``core/`` has no
opinion about how a rule is displayed.
"""

from __future__ import annotations

from pygments import highlight
from pygments.formatters.html import HtmlFormatter
from pygments.lexers.data import YamlLexer

_YAML_LEXER = YamlLexer()
# ``linenos=False`` — our CSS adds gutter marks for tier-2 errors via
# out-of-band decoration; Pygments-emitted line numbers would fight with
# that. ``nowrap=True`` skips the ``<div class="highlight">`` wrapper so
# our templates can place the content inside their own container.
_FORMATTER = HtmlFormatter(nowrap=True)


def yaml_to_html(text: str) -> str:
    """Return syntax-highlighted HTML for a YAML string.

    Output is a concatenation of ``<span class="…">…</span>`` elements
    styled by the ``.highlight *`` rules in ``intel2sigma.css``. Templates
    wrap this in a ``<pre class="highlight">`` themselves so gutter
    decoration can attach to specific lines later.
    """
    # Pygments' highlight() is typed as returning ``Any``; str() is a safe
    # explicit coercion that keeps mypy strict happy without an ignore.
    return str(highlight(text, _YAML_LEXER, _FORMATTER))


__all__ = ["yaml_to_html"]
