#!/bin/bash
# house-build/apply.sh BASE [BRANCH] - check out upstream BASE (tag or commit, detached) and cherry-pick the house commits
# onto it: every commit on BRANCH (default house) whose subject starts "House build", oldest first.
# "House base:" commits (moving house-build/BASE) are not picked. Fails, leaving the conflict in place, if a pick doesn't apply.
# Copy this script out of the tree before running it: the checkout replaces the working tree.
set -euo pipefail
BASE="$1"; BRANCH="${2:-house}"
PICKS=$(git log --reverse --no-merges --format='%H%x09%s' "$BRANCH" | awk -F'\t' '$2 ~ /^House build/ {print $1}')
[ -n "$PICKS" ] || { echo "no 'House build' commits on $BRANCH"; exit 1; }
echo "applying $(echo "$PICKS" | wc -l) house commits onto $BASE"
git checkout -q --detach "$BASE"
for c in $PICKS; do
  if ! git -c user.name="House build" -c user.email="house-build@users.noreply.github.com" cherry-pick -x "$c" >/dev/null; then
    echo "::error::house commit $(git log -1 --format='%h %s' "$c") does not apply on $BASE"
    git status --short | head -20
    exit 1
  fi
done
git log --oneline -n "$(echo "$PICKS" | wc -l)" | cat
