#!/usr/bin/env bash
set -euo pipefail

: "${GOOGLE_CLOUD_PROJECT:?Set GOOGLE_CLOUD_PROJECT to the deployed Google Cloud project ID.}"

event_type="${1:-merchant_denial}"
case "${event_type}" in
  merchant_denial) event_id="DEMO-DENIAL-$(date +%s)" ;;
  dispute_resolution) event_id="DEMO-RESOLUTION-$(date +%s)" ;;
  *) echo "Usage: $0 [merchant_denial|dispute_resolution]" >&2; exit 2 ;;
esac

gcloud pubsub topics publish caseworker-wake \
  --project="${GOOGLE_CLOUD_PROJECT}" \
  --message="{\"case_id\":\"CW-1042\",\"event_id\":\"${event_id}\",\"event_type\":\"${event_type}\"}"
