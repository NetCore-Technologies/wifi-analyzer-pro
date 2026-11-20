#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || { echo "Run inside the WiFi Analyzer Pro checkout." >&2; exit 2; }
cd "$ROOT"
[[ "$(git branch --show-current)" == "main" ]] || { echo "Only the existing main branch may be pushed." >&2; exit 2; }
git fetch --quiet origin main
BASE="$(git rev-parse origin/main)"
git merge-base --is-ancestor "$BASE" HEAD || { echo "Local main is not a fast-forward of origin/main. Refusing to push." >&2; exit 2; }
COUNT="$(git rev-list --count "$BASE..HEAD")"
[[ "$COUNT" -eq 50 ]] || { echo "Expected exactly 50 feature-pack commits ahead of origin/main; found $COUNT. Refusing to push." >&2; exit 2; }
[[ -z "$(git status --porcelain)" ]] || { echo "The worktree is not clean; reconcile before pushing." >&2; exit 2; }
if git log --format='%G?' "$BASE..HEAD" | grep -qv '^G$'; then
  echo "At least one commit is not locally signature-verified. Refusing to push." >&2
  exit 2
fi
MODULES=(wifi_analyzer_backend/feature_plugins/feature_[0-9][0-9][0-9]_*.py)
[[ "${#MODULES[@]}" -eq 100 ]] || { echo "Expected exactly 100 feature modules." >&2; exit 2; }
for file in "${MODULES[@]}"; do
  [[ "$(git log --format=%H "$BASE..HEAD" -- "$file" | wc -l)" -eq 1 ]] || {
    echo "Expected one dedicated commit per feature module: $file" >&2
    exit 2
  }
done
while IFS= read -r commit; do
  module_count="$(git diff-tree --no-commit-id --name-only -r "$commit" | grep -Ec '^wifi_analyzer_backend/feature_plugins/feature_[0-9]{3}_.+\.py$' || true)"
  [[ "$module_count" -eq 2 ]] || { echo "Commit $commit contains $module_count feature modules; expected two." >&2; exit 2; }
done < <(git rev-list --reverse "$BASE..HEAD")
python3 -m compileall -q wifi_analyzer_backend tests
python3 -m unittest discover -s tests -v
npm ci --no-audit --no-fund
npm run lint
npm run build
git diff --check
echo "All 50 signed commits and 100 feature modules verified. Pushing the existing main branch."
git push origin main
