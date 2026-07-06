#!/usr/bin/env bash
# install-hooks.sh — install git hooks for this repo
# Run once after cloning: bash scripts/install-hooks.sh

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HOOKS_DIR="$REPO_ROOT/.git/hooks"

cat > "$HOOKS_DIR/post-commit" <<'EOF'
#!/usr/bin/env bash
# post-commit hook: run devsnap when commit message contains [snap]

COMMIT_MSG=$(git log -1 --pretty=%s)

if echo "$COMMIT_MSG" | grep -q '\[snap\]'; then
  REPO_ROOT="$(git rev-parse --show-toplevel)"
  echo "📷 [snap] detected — running devsnap..."
  bash "$REPO_ROOT/scripts/devsnap.sh"
fi
EOF

chmod +x "$HOOKS_DIR/post-commit"
echo "✅ post-commit hook installed"
