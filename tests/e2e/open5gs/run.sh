#!/usr/bin/env bash
set -euo pipefail

test_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
compose_file="${test_dir}/compose.yaml"
profile_file="${test_dir}/register-smf.json"
log_file="${OPEN5GS_LOG_PATH:-/tmp/ngxora-open5gs-interop.log}"
nf_instance_id="c3b8f2c4-66bb-4a59-a334-715f25d9f3a5"

cleanup() {
  result=$?
  trap - EXIT
  if (( result != 0 )); then
    docker compose -f "${compose_file}" logs --no-color >"${log_file}" 2>&1 || true
    echo "Open5GS interop logs: ${log_file}" >&2
  fi
  docker compose -f "${compose_file}" down --volumes --remove-orphans >/dev/null 2>&1 || true
  exit "${result}"
}
trap cleanup EXIT

docker compose -f "${compose_file}" up --build --detach

nrf_port="$(docker compose -f "${compose_file}" port nrf 7777 | sed 's/.*://')"
proxy_port="$(docker compose -f "${compose_file}" port ngxora 8080 | sed 's/.*://')"
nrf_origin="http://127.0.0.1:${nrf_port}"
proxy_origin="http://127.0.0.1:${proxy_port}"

nrf_ready=false
for _ in {1..120}; do
  if curl --http2-prior-knowledge --silent --output /dev/null \
      "${nrf_origin}/nnrf-disc/v1/nf-instances?target-nf-type=SMF&requester-nf-type=SCP"; then
    nrf_ready=true
    break
  fi
  sleep 0.5
done
if [[ "${nrf_ready}" != true ]]; then
  echo "Open5GS NRF did not become ready" >&2
  exit 1
fi

curl --http2-prior-knowledge --fail --silent --show-error \
  --request PUT \
  --header 'content-type: application/json' \
  --data-binary "@${profile_file}" \
  "${nrf_origin}/nnrf-nfm/v1/nf-instances/${nf_instance_id}" \
  >/dev/null

proxy_ready=false
for _ in {1..60}; do
  if response="$(curl --fail --silent --show-error "${proxy_origin}/session" 2>/dev/null)" \
      && [[ "${response}" == *open5gs-producer* ]]; then
    proxy_ready=true
    break
  fi
  sleep 0.5
done
if [[ "${proxy_ready}" != true ]]; then
  echo "ngxora did not discover the Open5GS-registered producer" >&2
  exit 1
fi

curl --http2-prior-knowledge --fail --silent --show-error \
  --request DELETE \
  "${nrf_origin}/nnrf-nfm/v1/nf-instances/${nf_instance_id}" \
  >/dev/null

echo "Open5GS NRF interoperability test passed"
