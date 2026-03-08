#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SDK_DIR="${ROOT_DIR}/sdk/go"
PROTO_FILE="${ROOT_DIR}/crates/ngxora-runtime/proto/control.proto"
PROTO_DIR="${ROOT_DIR}/crates/ngxora-runtime/proto"
MODULE="github.com/paramoshka/ngxora/sdk/go"
BIN_DIR="${SDK_DIR}/bin"

mkdir -p "${BIN_DIR}"
export GOBIN="${BIN_DIR}"
export PATH="${BIN_DIR}:${PATH}"

ensure_tool() {
  local name="$1"
  local module="$2"

  if command -v "${name}" >/dev/null 2>&1; then
    return 0
  fi

  echo "installing ${name} from ${module}"
  go install "${module}"
}

ensure_tool protoc-gen-go google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.5
ensure_tool protoc-gen-go-grpc google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.5.1

PROTOC="${PROTOC:-$(cargo run -q --manifest-path "${ROOT_DIR}/crates/ngxora-runtime/Cargo.toml" --example print_protoc_path --locked)}"

rm -f "${SDK_DIR}"/ngxora/control/v1/*.pb.go

"${PROTOC}" \
  -I "${PROTO_DIR}" \
  --go_out="${SDK_DIR}" \
  --go_opt=module="${MODULE}" \
  --go-grpc_out="${SDK_DIR}" \
  --go-grpc_opt=module="${MODULE}" \
  "${PROTO_FILE}"

(
  cd "${SDK_DIR}"
  go mod tidy
)

echo "generated Go SDK under ${SDK_DIR}/ngxora/control/v1"
