#!/usr/bin/env bash
# Reports one release to Cursor Rollouts. A reporting failure never fails the release.
#
# Usage: report-rollouts-deployment.sh <bootstrap|start|finish>
#
# Required for every command:
#   CHANGE_MONITOR_ENV, CHANGE_MONITOR_SERVICE, CURSOR_API_KEY
#
# Required for start and finish:
#   DEPLOY_VERSION, DEPLOY_ACTOR
#
# Required for finish:
#   DEPLOY_OUTCOME=succeeded|failed|aborted
#   DEPLOY_FAILURE_MESSAGE when DEPLOY_OUTCOME=failed

set -u

command_name="${1:-}"
api_base="https://api.cursor.com/factory.v1.DeploymentsService"
deploy_source_uri="https://github.com/cogniumhq/cognium-dev"

if [[ "$command_name" != "bootstrap" && "$command_name" != "start" && "$command_name" != "finish" ]]; then
  echo "Usage: $0 <bootstrap|start|finish>" >&2
  exit 0
fi

for required in CHANGE_MONITOR_ENV CHANGE_MONITOR_SERVICE CURSOR_API_KEY; do
  if [[ -z "${!required:-}" ]]; then
    echo "Rollouts deployment report skipped: $required is not set" >&2
    exit 0
  fi
done

if ! command -v curl >/dev/null 2>&1 || ! command -v jq >/dev/null 2>&1; then
  echo "Rollouts deployment report skipped: curl and jq are required" >&2
  exit 0
fi

json_escape() {
  jq -Rn --arg value "$1" '$value'
}

factory_post() {
  local endpoint="$1" body="$2" response_file http_code
  response_file="$(mktemp)"
  http_code="$(
    curl --silent --show-error --location --max-time 20 \
      --output "$response_file" --write-out '%{http_code}' \
      --request POST "$api_base/$endpoint" \
      --header "Authorization: Bearer $token" \
      --header 'Content-Type: application/json' \
      --header 'Connect-Protocol-Version: 1' \
      --data "$body"
  )" || {
    rm -f "$response_file"
    return 1
  }
  printf '%s\n' "$http_code"
  cat "$response_file"
  rm -f "$response_file"
}

report_failure() {
  echo "Rollouts deployment report skipped: $1" >&2
  exit 0
}

token="$(
  curl --silent --show-error --location --max-time 20 --fail-with-body \
    --request POST 'https://api2.cursor.sh/auth/exchange_user_api_key' \
    --header "Authorization: Bearer $CURSOR_API_KEY" \
    --header 'Content-Type: application/json' \
    --data '{}' | jq -er '.accessToken'
)" || report_failure "could not exchange CURSOR_API_KEY"

case "$command_name" in
  bootstrap)
    environment_body="$(jq -nc --arg id "$CHANGE_MONITOR_ENV" \
      '{environmentId:$id,environment:{displayName:$id}}')"
    service_body="$(jq -nc --arg id "$CHANGE_MONITOR_SERVICE" \
      '{serviceId:$id,service:{displayName:$id}}')"
    environment_response="$(factory_post CreateEnvironment "$environment_body")" || report_failure "could not create environment"
    service_response="$(factory_post CreateService "$service_body")" || report_failure "could not create service"
    environment_code="${environment_response%%$'\n'*}"
    service_code="${service_response%%$'\n'*}"
    if [[ "$environment_code" != 2* && "$environment_code" != "409" ]]; then
      report_failure "CreateEnvironment returned HTTP $environment_code"
    fi
    if [[ "$service_code" != 2* && "$service_code" != "409" ]]; then
      report_failure "CreateService returned HTTP $service_code"
    fi
    ;;

  start|finish)
    for required in DEPLOY_VERSION DEPLOY_ACTOR; do
      if [[ -z "${!required:-}" ]]; then
        report_failure "$required is not set"
      fi
    done

    filter="$(printf 'environment = "environments/%s" AND deploy_version = "%s" AND service = "services/%s"' \
      "$CHANGE_MONITOR_ENV" "$DEPLOY_VERSION" "$CHANGE_MONITOR_SERVICE")"
    lookup_body="$(jq -nc --arg source "$deploy_source_uri" --arg filter "$filter" \
      '{deploySourceUri:$source,filter:$filter,pageSize:100,readMask:"events"}')"
    lookup_response="$(factory_post ListDeployments "$lookup_body")" || report_failure "could not look up deployment"
    lookup_code="${lookup_response%%$'\n'*}"
    lookup_json="${lookup_response#*$'\n'}"
    [[ "$lookup_code" == 2* ]] || report_failure "ListDeployments returned HTTP $lookup_code"

    deployment="$(printf '%s' "$lookup_json" | jq -c --arg actor "$DEPLOY_ACTOR" \
      'first(.deployments[]? | select(any(.events[]?; .actor == $actor))) // empty')" || report_failure "could not parse deployment lookup"
    deployment_name="$(printf '%s' "$deployment" | jq -er '.name' 2>/dev/null || true)"

    if [[ "$command_name" == "start" ]]; then
      if [[ -n "$deployment_name" ]]; then
        printf '%s\n' "$deployment_name"
        exit 0
      fi
      start_body="$(jq -nc \
        --arg source "$deploy_source_uri" \
        --arg environment "environments/$CHANGE_MONITOR_ENV" \
        --arg version "$DEPLOY_VERSION" \
        --arg service "services/$CHANGE_MONITOR_SERVICE" \
        --arg actor "$DEPLOY_ACTOR" \
        '{deployment:{deploySourceUri:$source,environment:$environment,deployVersion:$version,service:$service},event:{started:{},actor:$actor}}')"
      start_response="$(factory_post CreateDeployment "$start_body")" || report_failure "could not open deployment"
      start_code="${start_response%%$'\n'*}"
      start_json="${start_response#*$'\n'}"
      [[ "$start_code" == 2* ]] || report_failure "CreateDeployment returned HTTP $start_code"
      printf '%s' "$start_json" | jq -er '.deployment.name' || report_failure "deployment response has no name"
    else
      [[ -n "$deployment_name" ]] || report_failure "no deployment was opened for this release"
      case "${DEPLOY_OUTCOME:-}" in
        succeeded) event='{"completed":{"succeeded":{}}}' ;;
        failed) event="$(jq -nc --arg message "${DEPLOY_FAILURE_MESSAGE:-release failed}" '{completed:{failed:{message:$message}}}')" ;;
        aborted) event='{"aborted":{}}' ;;
        *) report_failure "DEPLOY_OUTCOME must be succeeded, failed, or aborted" ;;
      esac
      if [[ "$event" == *'"completed"'* ]] && printf '%s' "$deployment" | jq -e 'any(.events[]?; has("completed"))' >/dev/null; then
        echo "Rollouts deployment already completed"
        exit 0
      fi
      finish_body="$(jq -nc --arg name "$deployment_name" --arg actor "$DEPLOY_ACTOR" --argjson event "$event" \
        '{name:$name,event:($event + {actor:$actor})}')"
      finish_response="$(factory_post AppendDeploymentEvent "$finish_body")" || report_failure "could not close deployment"
      finish_code="${finish_response%%$'\n'*}"
      [[ "$finish_code" == 2* ]] || report_failure "AppendDeploymentEvent returned HTTP $finish_code"
    fi
    ;;
esac
