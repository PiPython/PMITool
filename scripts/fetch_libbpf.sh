#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="${ROOT}/third_party/libbpf"
VERSION="v1.5.0"

if [[ -d "${DEST}/.git" ]]; then
  echo "libbpf already present at ${DEST}"
  exit 0
fi

rm -rf "${DEST}"
mkdir -p "${ROOT}/third_party"
git clone --depth 1 --branch "${VERSION}" https://github.com/libbpf/libbpf.git "${DEST}"
echo "vendored libbpf ${VERSION} into ${DEST}"
