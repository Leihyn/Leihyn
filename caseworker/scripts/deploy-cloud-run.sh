#!/usr/bin/env bash
set -euo pipefail

: "${GOOGLE_CLOUD_PROJECT:?Set GOOGLE_CLOUD_PROJECT to the target Google Cloud project ID.}"

caseworker_region="${CASEWORKER_REGION:-us-central1}"
caseworker_service="${CASEWORKER_SERVICE:-caseworker}"
caseworker_model="${CASEWORKER_MODEL:-gemini-3.7-flash}"
runtime_account="caseworker-runtime@${GOOGLE_CLOUD_PROJECT}.iam.gserviceaccount.com"
push_account="caseworker-pubsub-push@${GOOGLE_CLOUD_PROJECT}.iam.gserviceaccount.com"

gcloud config set project "${GOOGLE_CLOUD_PROJECT}"
gcloud services enable \
  aiplatform.googleapis.com \
  cloudbuild.googleapis.com \
  firestore.googleapis.com \
  iamcredentials.googleapis.com \
  pubsub.googleapis.com \
  run.googleapis.com

gcloud iam service-accounts describe "${runtime_account}" >/dev/null 2>&1 || \
  gcloud iam service-accounts create caseworker-runtime --display-name="Caseworker runtime"
gcloud iam service-accounts describe "${push_account}" >/dev/null 2>&1 || \
  gcloud iam service-accounts create caseworker-pubsub-push --display-name="Caseworker Pub/Sub push"

for caseworker_role in roles/aiplatform.user roles/datastore.user; do
  gcloud projects add-iam-policy-binding "${GOOGLE_CLOUD_PROJECT}" \
    --member="serviceAccount:${runtime_account}" \
    --role="${caseworker_role}" \
    --condition=None >/dev/null
done

gcloud firestore databases describe --database='(default)' >/dev/null 2>&1 || \
  gcloud firestore databases create --database='(default)' --location="${caseworker_region}" --type=firestore-native

gcloud pubsub topics describe caseworker-wake >/dev/null 2>&1 || \
  gcloud pubsub topics create caseworker-wake

gcloud run deploy "${caseworker_service}" \
  --source=. \
  --region="${caseworker_region}" \
  --service-account="${runtime_account}" \
  --allow-unauthenticated \
  --set-env-vars="CASEWORKER_REPOSITORY=firestore,CASEWORKER_MODEL=${caseworker_model},GOOGLE_CLOUD_PROJECT=${GOOGLE_CLOUD_PROJECT},GOOGLE_CLOUD_LOCATION=${caseworker_region},GOOGLE_GENAI_USE_VERTEXAI=true"

caseworker_url="$(gcloud run services describe "${caseworker_service}" --region="${caseworker_region}" --format='value(status.url)')"

gcloud run services update "${caseworker_service}" \
  --region="${caseworker_region}" \
  --update-env-vars="CASEWORKER_PUBSUB_AUDIENCE=${caseworker_url},CASEWORKER_PUBSUB_SERVICE_ACCOUNT=${push_account}" >/dev/null

gcloud run services add-iam-policy-binding "${caseworker_service}" \
  --region="${caseworker_region}" \
  --member="serviceAccount:${push_account}" \
  --role="roles/run.invoker" >/dev/null

caseworker_project_number="$(gcloud projects describe "${GOOGLE_CLOUD_PROJECT}" --format='value(projectNumber)')"
gcloud projects add-iam-policy-binding "${GOOGLE_CLOUD_PROJECT}" \
  --member="serviceAccount:service-${caseworker_project_number}@gcp-sa-pubsub.iam.gserviceaccount.com" \
  --role="roles/iam.serviceAccountTokenCreator" \
  --condition=None >/dev/null

if gcloud pubsub subscriptions describe caseworker-wake-cloud-run >/dev/null 2>&1; then
  gcloud pubsub subscriptions update caseworker-wake-cloud-run \
    --push-endpoint="${caseworker_url}/api/events/pubsub" \
    --push-auth-service-account="${push_account}" \
    --push-auth-token-audience="${caseworker_url}"
else
  gcloud pubsub subscriptions create caseworker-wake-cloud-run \
    --topic=caseworker-wake \
    --push-endpoint="${caseworker_url}/api/events/pubsub" \
    --push-auth-service-account="${push_account}" \
    --push-auth-token-audience="${caseworker_url}"
fi

echo "Caseworker: ${caseworker_url}"
echo "Health:     ${caseworker_url}/api/health"
