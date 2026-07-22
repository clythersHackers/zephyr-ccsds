#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_dir=$(cd -- "$script_dir/../.." && pwd)
build_a=${BUILD_A:-$repo_dir/build-cfdp-udp-a}
build_b=${BUILD_B:-$repo_dir/build-cfdp-udp-b}
work_dir=${CFDP_UDP_WORK_DIR:-$repo_dir/build-cfdp-udp-results}

build_peers() {
    west build -b native_sim "$script_dir" -d "$build_a" --pristine -- \
        -DEXTRA_CONF_FILE=instance_a.conf
    west build -b native_sim "$script_dir" -d "$build_b" --pristine -- \
        -DEXTRA_CONF_FILE=instance_b.conf
}

run_case() {
    local name=$1
    local injection=$2
    local mode=$3
    local expected=$4
    local source=$work_dir/$name-source.bin
    local output=$work_dir/$name-received.bin
    local log_a=$work_dir/$name-a.log
    local log_b=$work_dir/$name-b.log
    local pid_a pid_b

    python3 - "$source" <<'PY'
import pathlib, sys
pathlib.Path(sys.argv[1]).write_bytes(bytes((i * 73 + 19) & 0xff for i in range(2049)))
PY
    : > "$output"

    CFDP_LOCAL_ENTITY=2 CFDP_REMOTE_ENTITY=1 CFDP_APID=0x340 \
        CFDP_OUTPUT="$output" \
        "$build_b/zephyr/zephyr.exe" >"$log_b" 2>&1 &
    pid_b=$!
    sleep 0.4
    CFDP_LOCAL_ENTITY=1 CFDP_REMOTE_ENTITY=2 CFDP_APID=0x340 \
        CFDP_SOURCE="$source" CFDP_SOURCE_NAME="$name.bin" \
        CFDP_DEST_NAME="$name.bin" CFDP_INJECT="$injection" CFDP_MODE="$mode" \
        "$build_a/zephyr/zephyr.exe" >"$log_a" 2>&1 &
    pid_a=$!

    for _ in $(seq 1 160); do
        if grep -q "CFDP_UDP STATUS.*status=$expected" "$log_b"; then
            break
        fi
        sleep 0.1
    done
    if ! grep -q "CFDP_UDP STATUS.*status=$expected" "$log_b"; then
        kill "$pid_a" "$pid_b" 2>/dev/null || true
        wait "$pid_a" 2>/dev/null || true
        wait "$pid_b" 2>/dev/null || true
        echo "$name did not reach receiver status $expected" >&2
        tail -20 "$log_b" >&2
        return 1
    fi
    sleep 1.1
    kill "$pid_a" "$pid_b" 2>/dev/null || true
    wait "$pid_a" 2>/dev/null || true
    wait "$pid_b" 2>/dev/null || true

    grep "CFDP_UDP STATUS" "$log_b" | tail -1
    if [[ $expected == COMPLETE ]]; then
        cmp "$source" "$output"
    elif [[ -s $output ]]; then
        echo "negative case unexpectedly committed output" >&2
        return 1
    fi
}

mkdir -p "$work_dir"
if [[ ${1:-} != --no-build ]]; then
    build_peers
fi

run_case success none ack COMPLETE
run_case drop-recovery drop ack COMPLETE
grep -q 'NAK_SENT' "$work_dir/drop-recovery-b.log"
grep -q 'RETRANSMIT' "$work_dir/drop-recovery-a.log"
run_case corruption corrupt unack FAILED
grep -q 'cfdp_status=CHECKSUM_FAILURE' "$work_dir/corruption-b.log"

echo "CFDP UDP integration: success, drop recovery, and corruption failure passed"
