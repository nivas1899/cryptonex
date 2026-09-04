#!/usr/bin/env bash
set -euo pipefail
# integrity check of downloaded build artefacts
md5sum -c artefacts.md5 || exit 1
echo "artefacts verified"
