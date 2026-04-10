#!/usr/bin/env bash
#
# Build and run the conformance suite against every SDK image.
# Run from the repo root:
#
#     ./sdks/run-conformance.sh            # all SDKs
#     ./sdks/run-conformance.sh python go  # selected SDKs only
#
# Requires docker. Exits non-zero if any SDK fails conformance.

set -euo pipefail

cd "$(dirname "$0")/.."

SDKS=(
  "go:.:Dockerfile"
  "python:sdks/python:sdks/python/Dockerfile"
  "typescript:sdks/typescript:sdks/typescript/Dockerfile"
  "ruby:sdks/ruby:sdks/ruby/Dockerfile"
  "php:sdks/php:sdks/php/Dockerfile"
  "kotlin:sdks/kotlin:sdks/kotlin/Dockerfile"
)

selected=("$@")

run_one() {
  local name="$1"
  local dockerfile="$2"
  local tag="crowdcontrol-${name}"

  echo
  echo "================================================================"
  echo "  ${name}"
  echo "================================================================"

  echo "-> building ${tag} from ${dockerfile}"
  docker build -f "${dockerfile}" -t "${tag}" . >/dev/null

  echo "-> running conformance suite"
  if docker run --rm "${tag}"; then
    echo "PASS: ${name}"
    return 0
  else
    echo "FAIL: ${name}"
    return 1
  fi
}

failed=()
passed=()

for entry in "${SDKS[@]}"; do
  IFS=":" read -r name _dir dockerfile <<< "${entry}"

  # If specific SDKs were requested, skip others.
  if [ "${#selected[@]}" -gt 0 ]; then
    skip=1
    for want in "${selected[@]}"; do
      if [ "${want}" = "${name}" ]; then skip=0; break; fi
    done
    if [ "${skip}" = "1" ]; then continue; fi
  fi

  if run_one "${name}" "${dockerfile}"; then
    passed+=("${name}")
  else
    failed+=("${name}")
  fi
done

echo
echo "================================================================"
echo "  summary"
echo "================================================================"
echo "passed: ${passed[*]:-none}"
echo "failed: ${failed[*]:-none}"

if [ "${#failed[@]}" -gt 0 ]; then
  exit 1
fi
