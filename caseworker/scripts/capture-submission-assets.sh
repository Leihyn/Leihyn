#!/usr/bin/env bash
set -euo pipefail

caseworker_url="${CASEWORKER_URL:-http://127.0.0.1:4180}"
chrome_binary="${CASEWORKER_CHROME:-/Applications/Google Chrome.app/Contents/MacOS/Google Chrome}"
asset_dir="${CASEWORKER_ASSET_DIR:-$(pwd)/submission-assets}"

mkdir -p "${asset_dir}"

capture() {
  local filename="$1"
  local url="$2"
  "${chrome_binary}" \
    --headless=new \
    --no-sandbox \
    --disable-gpu \
    --hide-scrollbars \
    --window-size=1440,960 \
    --screenshot="${asset_dir}/${filename}" \
    "${url}"
}

curl -fsS -X POST "${caseworker_url}/api/cases/demo" >/dev/null
capture "01-caseworker-evidence.png" "${caseworker_url}"
capture "02-exact-message-approval.png" "${caseworker_url}/?view=approval"

curl -fsS -X POST "${caseworker_url}/api/cases/CW-1042/actions/approve" \
  -H 'Content-Type: application/json' \
  -d '{"decided_by":"Maya Okeke"}' >/dev/null
curl -fsS -X POST "${caseworker_url}/api/cases/CW-1042/actions/execute" >/dev/null
capture "03-durable-checkpoint.png" "${caseworker_url}/?view=activity"

curl -fsS -X POST "${caseworker_url}/api/cases/CW-1042/events/demo-denial" >/dev/null
capture "04-evidence-backed-escalation.png" "${caseworker_url}/?view=approval"

curl -fsS -X POST "${caseworker_url}/api/cases/CW-1042/actions/approve" \
  -H 'Content-Type: application/json' \
  -d '{"decided_by":"Maya Okeke"}' >/dev/null
curl -fsS -X POST "${caseworker_url}/api/cases/CW-1042/actions/execute" >/dev/null
curl -fsS -X POST "${caseworker_url}/api/cases/CW-1042/events/demo-resolution" >/dev/null
capture "05-verified-resolution.png" "${caseworker_url}/?view=activity"

echo "Captured Devpost assets in ${asset_dir}"
