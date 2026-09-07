#!/usr/bin/env bash
set -euo pipefail

test_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
compose_file="${test_dir}/compose.yaml"
profile_a="${test_dir}/register-smf.json"
profile_b="${test_dir}/register-smf-b.json"
profile_standby="${test_dir}/register-smf-standby.json"
log_file="${OPEN5GS_LOG_PATH:-/tmp/ngxora-open5gs-interop.log}"
nf_instance_a="c3b8f2c4-66bb-4a59-a334-715f25d9f3a5"
nf_instance_b="b3b8f2c4-66bb-4a59-a334-715f25d9f3a6"
nf_instance_standby="a3b8f2c4-66bb-4a59-a334-715f25d9f3a7"

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

register_profile() {
  local nf_instance_id="$1"
  local profile_file="$2"
  curl --http2-prior-knowledge --fail --silent --show-error \
    --request PUT \
    --header 'content-type: application/json' \
    --data-binary "@${profile_file}" \
    "${nrf_origin}/nnrf-nfm/v1/nf-instances/${nf_instance_id}" \
    >/dev/null
}

register_profile "${nf_instance_a}" "${profile_a}"
register_profile "${nf_instance_b}" "${profile_b}"
register_profile "${nf_instance_standby}" "${profile_standby}"

discovery_response="$(curl --http2-prior-knowledge --fail --silent --show-error \
  "${nrf_origin}/nnrf-disc/v1/nf-instances?target-nf-type=SMF&requester-nf-type=SCP&service-names=nsmf-pdusession")"
for nf_instance_id in "${nf_instance_a}" "${nf_instance_b}" "${nf_instance_standby}"; do
  if ! grep -Fq "${nf_instance_id}" <<<"${discovery_response}"; then
    echo "Open5GS discovery omitted NF instance ${nf_instance_id}" >&2
    exit 1
  fi
done
for metadata in \
    '"priority"[[:space:]]*:[[:space:]]*10' \
    '"priority"[[:space:]]*:[[:space:]]*20' \
    '"capacity"[[:space:]]*:[[:space:]]*3' \
    '"capacity"[[:space:]]*:[[:space:]]*1'; do
  if ! grep -Eq "${metadata}" <<<"${discovery_response}"; then
    echo "Open5GS discovery did not preserve ${metadata}" >&2
    exit 1
  fi
done

proxy_ready=false
for _ in {1..60}; do
  if response="$(curl --connect-timeout 1 --max-time 2 --fail --silent --show-error \
      "${proxy_origin}/session" 2>/dev/null)" \
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

primary_a=0
primary_b=0
standby=0
for _ in {1..40}; do
  response="$(curl --connect-timeout 1 --max-time 2 --fail --silent --show-error \
    "${proxy_origin}/session")"
  case "${response}" in
    *open5gs-producer-a*) ((primary_a += 1)) ;;
    *open5gs-producer-b*) ((primary_b += 1)) ;;
    *open5gs-producer-standby*) ((standby += 1)) ;;
    *)
      echo "Unexpected Open5GS producer response: ${response}" >&2
      exit 1
      ;;
  esac
done
if (( primary_a != 30 || primary_b != 10 || standby != 0 )); then
  echo "Unexpected Open5GS service distribution: A=${primary_a} B=${primary_b} standby=${standby}" >&2
  exit 1
fi

scp_request() {
  curl --http2-prior-knowledge --connect-timeout 1 --max-time 5 --fail --silent --show-error \
    --header '3gpp-sbi-discovery-target-nf-type: SMF' \
    --header '3gpp-sbi-discovery-requester-nf-type: SCP' \
    --header '3gpp-sbi-discovery-service-names: nsmf-pdusession' \
    "$@" "${proxy_origin}/scp/nsmf-pdusession/v1/sm-contexts"
}

primary_a=0
primary_b=0
for _ in {1..40}; do
  response="$(scp_request)"
  case "${response}" in
    *open5gs-producer-a*) ((primary_a += 1)) ;;
    *open5gs-producer-b*) ((primary_b += 1)) ;;
    *) echo "Unexpected SCP producer: ${response}" >&2; exit 1 ;;
  esac
done
if (( primary_a != 30 || primary_b != 10 )); then
  echo "Unexpected SCP distribution: A=${primary_a} B=${primary_b}" >&2
  exit 1
fi
response="$(scp_request --header "3gpp-sbi-discovery-target-nf-instance-id: ${nf_instance_b}")"
[[ "${response}" == *open5gs-producer-b* ]]
response="$(scp_request --header "3gpp-sbi-routing-binding: bl=nf-instance; nfinst=${nf_instance_a}")"
[[ "${response}" == *open5gs-producer-a* ]]

docker compose -f "${compose_file}" stop producer producer-b >/dev/null
standby_ready=false
for _ in {1..60}; do
  if response="$(curl --connect-timeout 1 --max-time 2 --fail --silent --show-error \
      "${proxy_origin}/session" 2>/dev/null)" \
      && [[ "${response}" == *open5gs-producer-standby* ]]; then
    standby_ready=true
    break
  fi
  sleep 0.5
done
if [[ "${standby_ready}" != true ]]; then
  echo "ngxora did not fail over to the lower-priority Open5GS service" >&2
  exit 1
fi

scp_standby_ready=false
for _ in {1..60}; do
  if response="$(scp_request 2>/dev/null)" && [[ "${response}" == *open5gs-producer-standby* ]]; then
    scp_standby_ready=true
    break
  fi
  sleep 0.5
done
if [[ "${scp_standby_ready}" != true ]]; then
  echo "SCP did not fail over to the lower-priority service" >&2
  exit 1
fi

for nf_instance_id in "${nf_instance_a}" "${nf_instance_b}" "${nf_instance_standby}"; do
  curl --http2-prior-knowledge --fail --silent --show-error \
    --request DELETE \
    "${nrf_origin}/nnrf-nfm/v1/nf-instances/${nf_instance_id}" \
    >/dev/null
done

echo "Open5GS NRF interoperability test passed"
