#!/bin/sh
set -e
ARGS="scan"
[ -n "$INPUT_REPO" ] && ARGS="$ARGS --repo $INPUT_REPO"
[ -n "$INPUT_ORG" ] && ARGS="$ARGS --github-org $INPUT_ORG"
[ -n "$INPUT_FORMAT" ] && ARGS="$ARGS --format $INPUT_FORMAT"
[ -n "$INPUT_FAIL_ON" ] && ARGS="$ARGS --fail-on $INPUT_FAIL_ON"
[ -n "$INPUT_OUTPUT" ] && ARGS="$ARGS --output $INPUT_OUTPUT"
[ -n "$INPUT_TOKEN" ] && export GITHUB_TOKEN="$INPUT_TOKEN"
[ "$INPUT_VERBOSE" = "true" ] && ARGS="$ARGS --verbose"
[ "$INPUT_QUIET" = "true" ] && ARGS="$ARGS --quiet"
exec /usr/local/bin/exposure-check $ARGS
