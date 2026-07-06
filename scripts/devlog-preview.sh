#!/usr/bin/env bash
# devlog-preview.sh — render devlog/*.md into a single browsable HTML file
# Output: devlog/preview.html
# Usage: bash scripts/devlog-preview.sh [--open]

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEVLOG_DIR="$REPO_ROOT/devlog"
OUT="$DEVLOG_DIR/preview.html"
OPEN=0
[[ "${1:-}" == "--open" ]] && OPEN=1

# Collect entries newest-first
ENTRIES=$(ls -t "$DEVLOG_DIR"/*.md 2>/dev/null || true)
if [[ -z "$ENTRIES" ]]; then
  echo "No devlog entries found."
  exit 0
fi

# Convert one markdown file to an HTML fragment (no external tools needed)
md_to_html() {
  local file="$1"
  local out=""
  local in_code=0

  while IFS= read -r line || [[ -n "$line" ]]; do
    # Fenced code blocks
    if [[ "$line" =~ ^\`\`\` ]]; then
      if [[ $in_code -eq 0 ]]; then
        out+="<pre><code>"
        in_code=1
      else
        out+="</code></pre>"$'\n'
        in_code=0
      fi
      continue
    fi
    if [[ $in_code -eq 1 ]]; then
      # Escape HTML inside code blocks
      line="${line//&/&amp;}"
      line="${line//</&lt;}"
      line="${line//>/&gt;}"
      out+="$line"$'\n'
      continue
    fi

    # HTML comments → skip
    [[ "$line" =~ ^\<\!-- ]] && continue

    # Headings
    if [[ "$line" =~ ^###\ (.*) ]]; then
      out+="<h3>${BASH_REMATCH[1]}</h3>"$'\n'; continue; fi
    if [[ "$line" =~ ^##\ (.*) ]]; then
      out+="<h2>${BASH_REMATCH[1]}</h2>"$'\n'; continue; fi
    if [[ "$line" =~ ^#\ (.*) ]]; then
      out+="<h1>${BASH_REMATCH[1]}</h1>"$'\n'; continue; fi

    # Images — rewrite relative assets/ paths to be relative to preview.html location
    img_pat='^\!\[\]\((assets/[^)]+)\)'
    if [[ "$line" =~ $img_pat ]]; then
      out+="<img src=\"${BASH_REMATCH[1]}\" alt=\"\" style=\"max-width:100%;border-radius:4px;\">"$'\n'
      continue
    fi

    # Blockquote
    if [[ "$line" =~ ^\>\ (.*) ]]; then
      out+="<blockquote>${BASH_REMATCH[1]}</blockquote>"$'\n'; continue; fi

    # Horizontal rule
    if [[ "$line" =~ ^---$ ]]; then
      out+="<hr>"$'\n'; continue; fi

    # List items
    if [[ "$line" =~ ^[[:space:]]*-\ (.*) ]]; then
      out+="<li>${BASH_REMATCH[1]}</li>"$'\n'; continue; fi

    # Italic date line (_date_)
    if [[ "$line" =~ ^_(.+)_$ ]]; then
      out+="<p class=\"date\">${BASH_REMATCH[1]}</p>"$'\n'; continue; fi

    # Empty line → paragraph break
    if [[ -z "$line" ]]; then
      out+="<p></p>"$'\n'; continue; fi

    # Default: paragraph
    out+="<p>$line</p>"$'\n'
  done < "$file"

  echo "$out"
}

# Build HTML
{
cat <<'HEADER'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Threequencer — Devlog</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    background: #13131f;
    color: #cdd6f4;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    font-size: 16px;
    line-height: 1.7;
    padding: 40px 20px;
  }
  .site-title {
    font-family: monospace;
    font-size: 11px;
    letter-spacing: 0.15em;
    color: #6c7086;
    text-transform: uppercase;
    margin-bottom: 48px;
  }
  .entry {
    max-width: 680px;
    margin: 0 auto 64px;
    padding-bottom: 48px;
    border-bottom: 1px solid #1e1e2e;
  }
  .entry:last-child { border-bottom: none; }
  h1 { font-size: 1.5rem; font-weight: 600; color: #cdd6f4; margin-bottom: 4px; }
  h2 { font-size: 1rem; font-weight: 600; color: #89b4fa; margin: 24px 0 8px; text-transform: uppercase; letter-spacing: 0.08em; font-size: 11px; }
  h3 { font-size: 0.95rem; color: #a6adc8; margin: 16px 0 6px; }
  p { color: #a6adc8; margin-bottom: 12px; }
  p.date { font-size: 12px; color: #6c7086; margin-bottom: 20px; }
  p:empty { margin-bottom: 0; }
  img { display: block; margin: 16px 0; border: 1px solid #313244; border-radius: 4px; }
  blockquote {
    border-left: 3px solid #89b4fa;
    padding-left: 16px;
    color: #89b4fa;
    margin: 16px 0;
    font-style: italic;
  }
  pre {
    background: #1e1e2e;
    border: 1px solid #313244;
    border-radius: 4px;
    padding: 16px;
    overflow-x: auto;
    margin: 16px 0;
  }
  code { font-family: monospace; font-size: 13px; color: #cdd6f4; }
  li { margin-left: 20px; color: #a6adc8; }
  hr { border: none; border-top: 1px solid #1e1e2e; margin: 24px 0; }
  .meta { font-size: 11px; color: #45475a; margin-top: 24px; }
</style>
</head>
<body>
<div class="site-title">Threequencer &mdash; Build Log</div>
HEADER

for entry in $ENTRIES; do
  echo "<div class=\"entry\">"
  md_to_html "$entry"
  echo "</div>"
done

echo "</body></html>"
} > "$OUT"

echo "✅ Preview: $OUT"
[[ $OPEN -eq 1 ]] && xdg-open "$OUT" 2>/dev/null || true
