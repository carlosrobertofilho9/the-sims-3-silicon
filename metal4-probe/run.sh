#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
EXECUTABLE="$SCRIPT_DIR/build/Metal4Probe.app/Contents/MacOS/metal4-probe"

if [ ! -x "$EXECUTABLE" ]; then
  printf 'App bundle not found. Run ./compile.sh first.\n' >&2
  exit 2
fi

export MTL_DEBUG_LAYER="${MTL_DEBUG_LAYER:-1}"
export MTL_SHADER_VALIDATION="${MTL_SHADER_VALIDATION:-1}"
export MTL_SHADER_VALIDATION_REPORT_TO_STDERR="${MTL_SHADER_VALIDATION_REPORT_TO_STDERR:-1}"

exec "$EXECUTABLE" "$@"
