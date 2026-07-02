#!/bin/sh
set -e

ARGS="scan"
[ -n "$INPUT_REPO" ]   && ARGS="$ARGS --repo $INPUT_REPO"
[ -n "$INPUT_ORG" ]    && ARGS="$ARGS --github-org $INPUT_ORG"
[ -n "$INPUT_DOMAIN" ] && ARGS="$ARGS --domain $INPUT_DOMAIN"
[ -n "$INPUT_FORMAT" ] && ARGS="$ARGS --format $INPUT_FORMAT"
[ -n "$INPUT_FAIL_ON" ] && ARGS="$ARGS --fail-on $INPUT_FAIL_ON"
[ -n "$INPUT_OUTPUT" ] && ARGS="$ARGS --output $INPUT_OUTPUT"
[ -n "$INPUT_TOKEN" ]  && export GITHUB_TOKEN="$INPUT_TOKEN"
[ "$INPUT_VERBOSE" = "true" ] && ARGS="$ARGS --verbose"
[ "$INPUT_QUIET" = "true" ]   && ARGS="$ARGS --quiet"

# --- JSON sidecar for structured outputs ---
JSON_TMP=$(mktemp /tmp/ec-report.XXXXXX.json)
/usr/local/bin/exposure-check scan \
  $(echo "$ARGS" | sed 's/^scan //') \
  --format json --output "$JSON_TMP" --quiet 2>/dev/null || true

SCORE=0; TOTAL=0; CRITICAL=0; HIGH=0
if [ -f "$JSON_TMP" ] && [ -s "$JSON_TMP" ]; then
  SCORE=$(jq -r '.score // 0' "$JSON_TMP" 2>/dev/null || echo 0)
  TOTAL=$(jq -r '.findings | length // 0' "$JSON_TMP" 2>/dev/null || echo 0)
  CRITICAL=$(jq -r '[.findings[] | select(.severity == "CRITICAL")] | length' "$JSON_TMP" 2>/dev/null || echo 0)
  HIGH=$(jq -r '[.findings[] | select(.severity == "HIGH")] | length' "$JSON_TMP" 2>/dev/null || echo 0)
fi
rm -f "$JSON_TMP"

# --- Write GITHUB_OUTPUT ---
if [ -n "$GITHUB_OUTPUT" ]; then
  echo "score=$SCORE"       >> "$GITHUB_OUTPUT"
  echo "findings=$TOTAL"    >> "$GITHUB_OUTPUT"
  echo "critical=$CRITICAL" >> "$GITHUB_OUTPUT"
  echo "high=$HIGH"         >> "$GITHUB_OUTPUT"
  [ -n "$INPUT_OUTPUT" ] && echo "report=$INPUT_OUTPUT" >> "$GITHUB_OUTPUT"
fi

# --- SARIF generation ---
if [ "$INPUT_SARIF" = "true" ]; then
  SARIF_FILE="/tmp/exposure-check.sarif"
  /usr/local/bin/exposure-check scan \
    $(echo "$ARGS" | sed 's/^scan //') \
    --format sarif --output "$SARIF_FILE" --quiet 2>/dev/null || true
  if [ -n "$GITHUB_OUTPUT" ]; then
    echo "sarif-file=$SARIF_FILE" >> "$GITHUB_OUTPUT"
  fi
fi

# --- Step summary ---
if [ -n "$GITHUB_STEP_SUMMARY" ]; then
  cat >> "$GITHUB_STEP_SUMMARY" <<SUMMARY
### 🛡️ exposure-check results

| Metric | Value |
|--------|-------|
| **Posture Score** | $SCORE / 100 |
| **Total Findings** | $TOTAL |
| **Critical** | $CRITICAL |
| **High** | $HIGH |

SUMMARY
fi

# --- Run the actual scan (user-visible output) ---
exec /usr/local/bin/exposure-check $ARGS
