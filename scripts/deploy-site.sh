#!/usr/bin/env bash
# Build a clean dist/ with only website-relevant files, then deploy to Cloudflare Pages.
#
# Why this exists:
#   `wrangler pages deploy .` would upload node_modules/, sdk/python/.venv/, sibling
#   worker projects (api/, relay/), and internal strategy markdown — Pages does NOT
#   respect .gitignore or .assetsignore. Staging into dist/ is the reproducible fix.
#
# Usage:
#   ./scripts/deploy-site.sh                # deploys to production (main branch)
#   ./scripts/deploy-site.sh seo-preview    # deploys to a named preview branch

set -euo pipefail

BRANCH="${1:-main}"
PROJECT="air-site"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST="$ROOT/dist"

cd "$ROOT"

# Files & directories that ARE the public website.
PAGES=(index.html 404.html sitemap.xml robots.txt BingSiteAuth.xml _redirects)
DIRS=(assets about admin blog contact developers governance lookup note register specs whitepaper)

echo "── Staging dist/ ─────────────────────────────"
rm -rf "$DIST"
mkdir -p "$DIST"

for f in "${PAGES[@]}"; do
  [[ -f "$f" ]] || { echo "  ⚠  missing $f"; continue; }
  cp "$f" "$DIST/"
  echo "  + $f"
done

for d in "${DIRS[@]}"; do
  [[ -d "$d" ]] || { echo "  ⚠  missing $d/"; continue; }
  cp -r "$d" "$DIST/"
  echo "  + $d/"
done

echo ""
echo "── dist/ summary ─────────────────────────────"
du -sh "$DIST"
find "$DIST" -type f | wc -l | xargs echo "  file count:"

echo ""
echo "── Deploying to Cloudflare Pages ($PROJECT, branch=$BRANCH) ──"
npx wrangler pages deploy "$DIST" --project-name="$PROJECT" --branch="$BRANCH" --commit-dirty=true
