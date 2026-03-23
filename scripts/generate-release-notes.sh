#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="${1:-dist}"

version="$(grep -E '^version\s*=' Cargo.toml | head -n1 | sed -E 's/version\s*=\s*"([^"]+)"/\1/')"
if [[ -z "$version" ]]; then
  echo "Unable to resolve version from Cargo.toml" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"

if [[ -n "${GITHUB_REF_NAME:-}" && "${GITHUB_REF_NAME}" == v* ]]; then
  release_tag="${GITHUB_REF_NAME}"
else
  release_tag="v${version}"
fi

previous_tag="$(git tag --sort=-creatordate | grep -Fxv "$release_tag" | head -n1 || true)"
if [[ -n "$previous_tag" ]]; then
  range="${previous_tag}..HEAD"
else
  range="HEAD"
fi

commits="$(git log --pretty=format:'%s|%h' "$range")"
if [[ -z "$commits" ]]; then
  commits="chore: release metadata refresh|HEAD"
fi

notes_file="$OUT_DIR/RELEASE_NOTES.md"
changelog_file="$OUT_DIR/CHANGELOG.md"
today="$(date -u +%Y-%m-%d)"

{
  echo "# Release Notes ${release_tag}"
  echo
  echo "- Date: ${today} (UTC)"
  echo "- Version: ${version}"
  if [[ -n "$previous_tag" ]]; then
    echo "- Diff: ${previous_tag}..${release_tag}"
  else
    echo "- Diff: initial release snapshot"
  fi
  echo
  echo "## Highlights"
  echo
} > "$notes_file"

declare -A section_title=(
  [feat]="Features"
  [fix]="Fixes"
  [security]="Security"
  [perf]="Performance"
  [refactor]="Refactor"
  [docs]="Docs"
  [test]="Tests"
  [build]="Build"
  [chore]="Chore"
  [other]="Other"
)

declare -A section_items

while IFS='|' read -r subject short_sha; do
  type="other"
  text="$subject"
  if [[ "$subject" =~ ^(feat|fix|security|perf|refactor|docs|test|build|chore)(\([^)]+\))?!?:[[:space:]]*(.+)$ ]]; then
    type="${BASH_REMATCH[1]}"
    text="${BASH_REMATCH[3]}"
  fi
  section_items["$type"]+="- ${text} (${short_sha})"$'\n'
done <<< "$commits"

for key in feat fix security perf refactor docs test build chore other; do
  if [[ -n "${section_items[$key]:-}" ]]; then
    {
      echo "### ${section_title[$key]}"
      echo
      printf "%s" "${section_items[$key]}"
      echo
    } >> "$notes_file"
  fi
done

{
  echo "# Changelog"
  echo
  echo "## ${release_tag} - ${today}"
  echo
  if [[ -n "$previous_tag" ]]; then
    echo "_Diff_: ${previous_tag}..${release_tag}"
  else
    echo "_Diff_: initial release snapshot"
  fi
  echo
  cat "$notes_file" | sed -n '/^## Highlights/,$p' | sed '1d'
} > "$changelog_file"

echo "Generated release metadata:"
echo "  $notes_file"
echo "  $changelog_file"
