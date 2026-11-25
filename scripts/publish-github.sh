#!/usr/bin/env bash
# Ручна дія власника GitHub: створює НОВИЙ приватний репозиторій з поточної теки.
# Використання: bash scripts/publish-github.sh [owner/repo]
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ ! -f README.md || ! -d crypto_lab ]]; then
  echo "Run only inside the extracted PR3-4 project." >&2
  exit 1
fi
command -v gh >/dev/null || { echo "Install GitHub CLI (gh)." >&2; exit 1; }
gh auth status >/dev/null 2>&1 || { echo "Login with: gh auth login" >&2; exit 1; }
login="$(gh api user --jq '.login')"
uid="$(gh api user --jq '.id')"
target="${1:-${login}/pr3-4-crypto}"
if gh repo view "$target" >/dev/null 2>&1; then
  echo "Repository $target already exists. Refusing to overwrite it." >&2
  exit 1
fi
if [[ -e .git ]]; then
  echo "This folder already has a git repository. Publish manually to avoid changing existing history." >&2
  exit 1
fi
echo "Destination: private GitHub repository https://github.com/$target"
read -r -p "Create this private repository and push project? [y/N] " answer
[[ "$answer" == 'y' || "$answer" == 'Y' ]] || { echo "Cancelled."; exit 0; }
git init -b main
git config user.name "$login"
git config user.email "${uid}+${login}@users.noreply.github.com"
git add -A
git commit -m "Implement AES RSA and hybrid encryption lab PR3-4"
gh repo create "$target" --private --source=. --remote=origin --push
printf 'Project uploaded: https://github.com/%s\n' "$target"
