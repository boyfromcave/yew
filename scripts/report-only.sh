#!/usr/bin/env bash
# report-only.sh RC BLOCKING NAME: end a CI step by its test's exit code RC. A blocking step fails
# with RC; a report-only one (BLOCKING != true) exits 0, so its check stays green, and records the
# result in the step summary and as the step output `failed` (for the log upload).
set -euo pipefail
rc=$1 blocking=$2 name=$3
if [ "$rc" -eq 0 ]; then
  echo "- $name: passed" >> "${GITHUB_STEP_SUMMARY:-/dev/null}"
  exit 0
fi
echo "failed=true" >> "${GITHUB_OUTPUT:-/dev/null}"
if [ "$blocking" = true ]; then
  exit "$rc"
fi
echo "::warning::$name failed (exit $rc), report-only"
echo "- $name: **failed** (exit $rc), report-only: the check stays green" >> "${GITHUB_STEP_SUMMARY:-/dev/null}"
