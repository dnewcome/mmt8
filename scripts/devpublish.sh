#!/usr/bin/env bash
# devpublish.sh — promote a devlog entry to dnuke.com
# Usage: devpublish <devlog entry .md file>
#
# Reads project slug/name from .project.toml in the current repo.
# Copies entry + screenshot into the dnuke.com src tree and builds the site.
# Set DNUKE_ROOT env var to override the default dnuke.com path (../dnuke.com).

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
TOML="$REPO_ROOT/.project.toml"
DNUKE_ROOT="${DNUKE_ROOT:-$REPO_ROOT/../dnuke.com}"

# Read project identity from .project.toml, or fall back to dnuke-com
if [[ -f "$TOML" ]]; then
  PROJECT_SLUG=$(grep '^slug' "$TOML" | sed 's/.*= "\(.*\)"/\1/')
  PROJECT_NAME=$(grep '^name' "$TOML" | sed 's/.*= "\(.*\)"/\1/')
else
  PROJECT_SLUG="dnuke-com"
  PROJECT_NAME="dnuke.com"
fi

SOURCE="${1:-}"
if [[ -z "$SOURCE" ]]; then
  echo "Usage: devpublish <devlog entry .md file>"
  echo ""
  echo "Recent entries:"
  ls -t "$REPO_ROOT/devlog/"*.md 2>/dev/null | head -10 | sed 's|.*/||'
  exit 1
fi

[[ "$SOURCE" != /* ]] && SOURCE="$REPO_ROOT/$SOURCE"

if [[ ! -f "$SOURCE" ]]; then
  echo "Error: $SOURCE not found"
  exit 1
fi

# Derive date and basename from filename (YYYY-MM-DD-HHmmss-slug.md)
BASENAME=$(basename "$SOURCE" .md)
DATE_PART=$(echo "$BASENAME" | grep -oE '^[0-9]{4}-[0-9]{2}-[0-9]{2}')

# Extract title: strip conventional commit prefix (type: ) from first H1
RAW_TITLE=$(grep -m1 '^# ' "$SOURCE" | sed 's/^# //')
TITLE=$(echo "$RAW_TITLE" | sed 's/^[a-z]*: //')

# Strip the H1 line from body (frontmatter carries the title)
BODY=$(sed '1{/^# /d;}' "$SOURCE")

# Ensure destination dirs exist
DEST_DIR="$DNUKE_ROOT/src/devlog/$PROJECT_SLUG"
IMG_DIR="$DNUKE_ROOT/src/images/devlog/$PROJECT_SLUG"
mkdir -p "$DEST_DIR" "$IMG_DIR"

# Create index.njk for the project if it doesn't exist yet
INDEX="$DEST_DIR/index.njk"
if [[ ! -f "$INDEX" ]]; then
  cat > "$INDEX" <<NJKEOF
---
layout: base.njk
title: "$PROJECT_NAME — Devlog"
project: $PROJECT_SLUG
project_name: $PROJECT_NAME
permalink: /devlog/$PROJECT_SLUG/
---
<div class="blog-container">
  <div class="post-meta" style="margin-bottom:8px;">
    <a href="/devlog/">← All devlog entries</a>
  </div>
  <div class="page-title">$PROJECT_NAME</div>
  <p style="color:#888; font-size:14px; margin-bottom:32px;">
    Build log for $PROJECT_NAME.
  </p>
  <ul class="post-list">
    {%- for post in collections.devlog %}
      {%- if post.data.project == "$PROJECT_SLUG" %}
      <li class="post-item">
        <div class="post-meta">{{ post.date | dateFormat }}</div>
        <div class="post-title"><a href="{{ post.url }}">{{ post.data.title }}</a></div>
        {%- if post.templateContent %}
        <div class="post-excerpt">{{ post.templateContent | excerpt }}</div>
        {%- endif %}
      </li>
      {%- endif %}
    {%- endfor %}
  </ul>
</div>
NJKEOF
  echo "   Created $DEST_DIR/index.njk"
fi

# Copy screenshot and rewrite image path in body
SCREENSHOT=$(grep -oE '\!\[\]\(assets/[^)]+\)' "$SOURCE" | sed 's/!\[\](\(.*\))/\1/' || true)
if [[ -n "$SCREENSHOT" ]]; then
  SRC_IMG="$REPO_ROOT/devlog/$SCREENSHOT"
  IMG_BASENAME=$(basename "$SCREENSHOT")
  if [[ -f "$SRC_IMG" ]]; then
    cp "$SRC_IMG" "$IMG_DIR/$IMG_BASENAME"
    echo "   Copied image → src/images/devlog/$PROJECT_SLUG/$IMG_BASENAME"
    BODY=$(echo "$BODY" | sed "s|assets/${IMG_BASENAME}|/images/devlog/${PROJECT_SLUG}/${IMG_BASENAME}|g")
  fi
fi

# Write entry with Eleventy frontmatter
DEST_FILE="$DEST_DIR/$BASENAME.md"
{
  echo "---"
  echo "layout: devlog-post.njk"
  echo "title: \"$TITLE\""
  echo "date: $DATE_PART"
  echo "project: $PROJECT_SLUG"
  echo "project_name: $PROJECT_NAME"
  echo "tags:"
  echo "  - devlog"
  echo "  - $PROJECT_SLUG"
  echo "---"
  echo ""
  echo "$BODY"
} > "$DEST_FILE"

echo "✅ Published: $DEST_FILE"
echo "   Project: $PROJECT_NAME ($PROJECT_SLUG)"
echo "   Title:   $TITLE"
echo "   Date:    $DATE_PART"
echo ""

# Build dnuke.com to verify the entry renders before publishing
echo "🔨 Building dnuke.com..."
BUILD_LOG="$(mktemp)"
if (cd "$DNUKE_ROOT" && npm run build) >"$BUILD_LOG" 2>&1; then
  echo "   build ok"
else
  echo "❌ dnuke.com build failed — not publishing:"
  tail -12 "$BUILD_LOG"
  rm -f "$BUILD_LOG"
  exit 1
fi
rm -f "$BUILD_LOG"
echo ""

# Commit + push dnuke.com → triggers the DigitalOcean deploy.
# Escape hatch: run with DEVPUBLISH_PUSH=0 to stage the change and push yourself.
if [[ "${DEVPUBLISH_PUSH:-1}" == "1" ]]; then
  echo "📤 Publishing to dnuke.com..."
  (
    cd "$DNUKE_ROOT"
    git add "src/devlog/$PROJECT_SLUG"
    [ -d "src/images/devlog/$PROJECT_SLUG" ] && git add "src/images/devlog/$PROJECT_SLUG"
    if git diff --cached --quiet; then
      echo "   (nothing new to publish)"
    else
      git commit -q -m "devlog($PROJECT_SLUG): $TITLE"
      git push -q
      echo "   ✅ pushed — DigitalOcean will redeploy dnuke.com shortly"
    fi
  )
else
  echo "DEVPUBLISH_PUSH=0 — staged only. Next: cd $DNUKE_ROOT && git add -p && git commit && git push"
fi
