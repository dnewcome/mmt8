#!/usr/bin/env bash
# devsnap.sh — capture a devlog snapshot
# Usage: scripts/devsnap.sh [--note "optional note"] [--port 9001] [--no-screenshot] [--window]
#
# Screenshot modes (tried in order unless --window is set):
#   default : Chrome headless — good for CI/no display, but no WebGL
#             tries http://localhost:$PORT then http://127.0.0.1:$PORT
#   --window: grab the live window showing the app — captures real WebGL visuals
#             macOS: AppleScript window bounds + screencapture; falls back to Chrome headless
#                    if Screen Recording permission is denied (empty file check)
#             Wayland: grim or GNOME PrtSc prompt
#             X11: xdotool + import
#
# Reads DEVSNAP_PORT env var for port (default 9001).
# Creates devlog/YYYY-MM-DD-HHmmss-<slug>.md with screenshot if server is up.

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
DEVLOG_DIR="$REPO_ROOT/devlog"
ASSETS_DIR="$DEVLOG_DIR/assets"
PORT="${DEVSNAP_PORT:-9001}"
NOTE=""
SKIP_SCREENSHOT=0
WINDOW_MODE=0

# Parse args
while [[ $# -gt 0 ]]; do
  case "$1" in
    --note) NOTE="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --no-screenshot) SKIP_SCREENSHOT=1; shift ;;
    --window) WINDOW_MODE=1; shift ;;
    *) NOTE="$1"; shift ;;
  esac
done

DATE=$(date +%Y-%m-%d)
TIMESTAMP=$(date +%Y-%m-%d-%H%M%S)

# Build slug from commit message or note
COMMIT_MSG=$(git -C "$REPO_ROOT" log -1 --pretty=%s 2>/dev/null || echo "snapshot")
# Strip [snap] tag and sanitize to slug
RAW_SLUG="${NOTE:-$COMMIT_MSG}"
SLUG=$(echo "$RAW_SLUG" | sed 's/\[snap\]//g' | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]/-/g' | sed 's/--*/-/g' | sed 's/^-//;s/-$//' | cut -c1-48)

ENTRY_FILE="$DEVLOG_DIR/${TIMESTAMP}-${SLUG}.md"
SCREENSHOT_FILE="$ASSETS_DIR/${TIMESTAMP}-${SLUG}.png"
SCREENSHOT_REL="assets/${TIMESTAMP}-${SLUG}.png"

mkdir -p "$ASSETS_DIR"

# --- Helpers ---

# find_chrome: sets CHROME_BIN to the first available Chrome/Chromium binary
find_chrome() {
  CHROME_BIN=""
  for candidate in \
    google-chrome \
    google-chrome-stable \
    chromium \
    chromium-browser \
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
    "/Applications/Chromium.app/Contents/MacOS/Chromium"
  do
    if command -v "$candidate" &>/dev/null || [[ -x "$candidate" ]]; then
      CHROME_BIN="$candidate"
      return
    fi
  done
}

# find_server_url: sets SERVER_URL to the first responsive URL on PORT
# tries localhost then 127.0.0.1 (needed when app uses 127.0.0.1 as bind address)
find_server_url() {
  SERVER_URL=""
  for url in "http://localhost:$PORT" "http://127.0.0.1:$PORT"; do
    if curl -sf --max-time 2 "$url" > /dev/null 2>&1; then
      SERVER_URL="$url"
      return
    fi
  done
}

# chrome_headless: take a headless screenshot of SERVER_URL; sets SCREENSHOT_OK=1 on success
chrome_headless() {
  find_chrome
  find_server_url
  if [[ -z "$SERVER_URL" ]]; then
    SCREENSHOT_STATUS="server not running on port $PORT"
    echo "⚠️  Server not running on port $PORT — skipping screenshot"
    return
  fi
  echo "📸 Taking screenshot of $SERVER_URL ..."
  if [[ -z "$CHROME_BIN" ]]; then
    SCREENSHOT_STATUS="chrome not found"
    echo "⚠️  Chrome/Chromium not found — skipping screenshot"
  else
    "$CHROME_BIN" \
      --headless=new \
      --disable-gpu \
      --no-sandbox \
      --window-size=1280,720 \
      --screenshot="$SCREENSHOT_FILE" \
      "$SERVER_URL" \
      2>/dev/null \
      && SCREENSHOT_OK=1 \
      && SCREENSHOT_STATUS="captured (headless)" \
      || SCREENSHOT_STATUS="chrome failed"
  fi
}

# --- Screenshot ---
SCREENSHOT_STATUS="no screenshot"
SCREENSHOT_OK=0

if [[ $SKIP_SCREENSHOT -eq 0 ]]; then

  if [[ $WINDOW_MODE -eq 1 ]]; then
    # Window mode: capture the live screen (shows real WebGL)
    echo "📸 Capturing live screen..."

    if [[ "$OSTYPE" == "darwin"* ]]; then
      # macOS — use screencapture with AppleScript window bounds
      # NOTE: screencapture requires Screen Recording permission. If denied, it
      # creates an empty or very small file. We check file size and fall back to
      # Chrome headless if that happens.
      BOUNDS=$(osascript 2>/dev/null <<'APPLESCRIPT'
set appNames to {"Google Chrome", "Chromium", "Safari", "Firefox"}
repeat with appName in appNames
  try
    tell application appName
      if (count of windows) > 0 then
        set b to bounds of front window
        return ((item 1 of b) as string) & "," & ((item 2 of b) as string) & "," & ((item 3 of b) as string) & "," & ((item 4 of b) as string)
      end if
    end tell
  end try
end repeat
return ""
APPLESCRIPT
)
      if [[ -n "$BOUNDS" ]]; then
        X=$(echo "$BOUNDS" | cut -d',' -f1 | xargs)
        Y=$(echo "$BOUNDS" | cut -d',' -f2 | xargs)
        W=$(echo "$BOUNDS" | cut -d',' -f3 | xargs)
        H=$(echo "$BOUNDS" | cut -d',' -f4 | xargs)
        W=$((W - X))
        H=$((H - Y))
        echo "   Capturing browser window at ${X},${Y} ${W}×${H}"
        screencapture -x -R "${X},${Y},${W},${H}" "$SCREENSHOT_FILE" 2>/dev/null \
          && SCREENSHOT_STATUS="captured (window)" \
          || SCREENSHOT_STATUS="screencapture failed"
      else
        echo "   Browser window not found — capturing full screen"
        screencapture -x "$SCREENSHOT_FILE" 2>/dev/null \
          && SCREENSHOT_STATUS="captured (full screen)" \
          || SCREENSHOT_STATUS="screencapture failed"
      fi

      # Check if screencapture was denied Screen Recording permission
      # (produces an empty or <5KB stub file)
      if [[ -f "$SCREENSHOT_FILE" ]]; then
        FILE_SIZE=$(wc -c < "$SCREENSHOT_FILE" | xargs)
        if [[ "$FILE_SIZE" -gt 5120 ]]; then
          SCREENSHOT_OK=1
        else
          echo "⚠️  screencapture produced a tiny file ($FILE_SIZE bytes) — Screen Recording permission likely denied"
          echo "   Falling back to Chrome headless..."
          rm -f "$SCREENSHOT_FILE"
          SCREENSHOT_STATUS="no screenshot"
          chrome_headless
        fi
      fi

    elif [[ "${XDG_SESSION_TYPE:-}" == "wayland" ]] || [[ -n "${WAYLAND_DISPLAY:-}" ]]; then
      # Wayland path
      if command -v grim &>/dev/null && grim "$SCREENSHOT_FILE" 2>/dev/null; then
        SCREENSHOT_OK=1
        SCREENSHOT_STATUS="captured (grim/wayland)"
      else
        # GNOME Wayland: PrtSc saves to ~/Pictures/Screenshots — wait for user
        SHOTS_DIR="$HOME/Pictures/Screenshots"
        mkdir -p "$SHOTS_DIR"
        BEFORE=$(ls -t "$SHOTS_DIR"/*.png 2>/dev/null | head -1 || true)
        echo ""
        echo "  ┌─────────────────────────────────────────────────┐"
        echo "  │  Press PrtSc to take a screenshot, then         │"
        echo "  │  press Enter here when done.                    │"
        echo "  └─────────────────────────────────────────────────┘"
        read -r _
        AFTER=$(ls -t "$SHOTS_DIR"/*.png 2>/dev/null | head -1 || true)
        if [[ -n "$AFTER" && "$AFTER" != "$BEFORE" ]]; then
          cp "$AFTER" "$SCREENSHOT_FILE"
          SCREENSHOT_OK=1
          SCREENSHOT_STATUS="captured (gnome prtsc)"
        else
          echo "⚠️  No new screenshot detected in $SHOTS_DIR"
          SCREENSHOT_STATUS="no new screenshot"
        fi
      fi

    else
      # X11 path
      WIN_ID=""
      if command -v xdotool &>/dev/null; then
        WIN_ID=$(xdotool search --onlyvisible --name "Threequencer" 2>/dev/null | head -1 || true)
        [[ -z "$WIN_ID" ]] && WIN_ID=$(xdotool search --onlyvisible --name "localhost:$PORT" 2>/dev/null | head -1 || true)
        [[ -z "$WIN_ID" ]] && WIN_ID=$(xdotool search --onlyvisible --name "localhost" 2>/dev/null | head -1 || true)
      fi
      if [[ -n "$WIN_ID" ]]; then
        echo "   Found window $WIN_ID via xdotool"
        import -window "$WIN_ID" "$SCREENSHOT_FILE" 2>/dev/null \
          && SCREENSHOT_OK=1 \
          && SCREENSHOT_STATUS="captured (window)" \
          || SCREENSHOT_STATUS="import failed"
      else
        echo "   Window not found — capturing full screen"
        import -window root "$SCREENSHOT_FILE" 2>/dev/null \
          && SCREENSHOT_OK=1 \
          && SCREENSHOT_STATUS="captured (full screen)" \
          || SCREENSHOT_STATUS="import failed"
      fi
    fi

  else
    # Default mode: Chrome headless
    chrome_headless
  fi
fi

# --- Git context ---
GIT_HASH=$(git -C "$REPO_ROOT" log -1 --pretty=%h 2>/dev/null || echo "")
GIT_MSG=$(git -C "$REPO_ROOT" log -1 --pretty=%s 2>/dev/null || echo "")
GIT_DATE=$(git -C "$REPO_ROOT" log -1 --pretty=%ci 2>/dev/null || date)
FILES_CHANGED=$(git -C "$REPO_ROOT" diff --name-only HEAD~1 HEAD 2>/dev/null | head -20 | sed 's/^/  - /' || echo "  (no diff)")

# --- Write entry ---
{
  echo "# ${NOTE:-$GIT_MSG}"
  echo ""
  echo "_${DATE}_"
  echo ""
  if [[ $SCREENSHOT_OK -eq 1 ]]; then
    echo "![]($SCREENSHOT_REL)"
    echo ""
  fi
  echo "## What happened"
  echo ""
  echo "<!-- Claude or you: fill this in -->"
  echo ""
  if [[ -n "$NOTE" ]]; then
    echo "> $NOTE"
    echo ""
  fi
  echo "## Files touched"
  echo ""
  echo "$FILES_CHANGED"
  echo ""
  echo "## Tweet draft"
  echo ""
  echo "<!-- fill me in -->"
  echo ""
  echo "---"
  echo ""
  echo "_commit: ${GIT_HASH} · screenshot: ${SCREENSHOT_STATUS}_"
} > "$ENTRY_FILE"

echo "✅ Devlog entry: $ENTRY_FILE"
if [[ $SCREENSHOT_OK -eq 1 ]]; then
  echo "   Screenshot: $SCREENSHOT_FILE"
fi
