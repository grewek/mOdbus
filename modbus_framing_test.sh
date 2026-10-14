#!/usr/bin/env bash
#
# Tests the framing of a Modbus TCP server using netcat.
#
# Usage:
#   ./modbus_framing_test.sh [fast|slow|all] [host] [port]
#
#   fast  All frames are sent at once.
#   slow  Frames are sent in chunks with pauses in between.
#   all   Both, one after the other (default).
#
# Environment variables:
#   DELAY       Pause between chunks in seconds               (default: 1)
#   BYTE_DELAY  Pause for the byte-by-byte test in seconds    (default: 0.3)
#   HOLD        How long the connection stays open after
#               sending, so responses can arrive              (default: 2)
#   TIMEOUT     Hard upper limit per test in seconds          (default: 30)
#   NC_OPTS     Options for nc. Detected automatically, but can be
#               overridden, e.g. NC_OPTS="-N" or "-q 1".
#
# Note: The server handles connections one after another. Each test opens
# its own connection and closes it at the end.

set -u

MODE="${1:-all}"
HOST="${2:-127.0.0.1}"
PORT="${3:-10502}"
DELAY="${DELAY:-1}"
BYTE_DELAY="${BYTE_DELAY:-0.3}"
HOLD="${HOLD:-2}"
TIMEOUT="${TIMEOUT:-30}"

# ---------------------------------------------------------------------------
# Test frames, 12 bytes each, as hex bytes separated by spaces
#
#            TID   PID   LEN   UID FC ADDR  QTY
FRAME_1="00 01 00 00 00 06 01  03 00 00 00 0a"  # TID 1, 10 registers from address 0
FRAME_2="00 02 00 00 00 06 01  03 00 0a 00 05"  # TID 2,  5 registers from address 10
FRAME_3="00 03 00 00 00 06 01  03 00 00 00 01"  # TID 3,  1 register  from address 0
FRAME_BAD="00 04 00 01 00 06 01 03 00 00 00 01" # TID 4, protocol ID 1 -> invalid

# ---------------------------------------------------------------------------
# Helper functions

# Writes hex bytes like "00 01 0a" as raw bytes.
emit() {
    local out=""
    local b
    for b in $1; do
        out+="\\x$b"
    done
    printf "$out"
}

# Sends all bytes at once.
send_now() {
    emit "$1"
}

# Sends the given chunks with DELAY seconds of pause in between.
send_chunks() {
    local first=1
    local chunk
    for chunk in "$@"; do
        if [ "$first" -eq 0 ]; then
            sleep "$DELAY"
        fi
        first=0
        emit "$chunk"
    done
}

# Splits the bytes into chunks of a fixed size and sends them with a pause.
#   $1 chunk size in bytes
#   $2 pause in seconds
#   $3 hex bytes
send_pieces() {
    local size="$1"
    local pause="$2"
    local -a bytes=($3)
    local i
    for (( i = 0; i < ${#bytes[@]}; i += size )); do
        if (( i > 0 )); then
            sleep "$pause"
        fi
        emit "${bytes[*]:i:size}"
    done
}

# Detects which option makes nc close the connection once its input ends.
# Without it, some variants wait forever for the server.
detect_nc_opts() {
    if [ -n "${NC_OPTS+x}" ]; then
        return
    fi
    local help
    help="$(nc -h 2>&1)"
    if grep -qE -- '(^|[[:space:]])-N([[:space:]]|$)' <<<"$help"; then
        NC_OPTS="-N"        # OpenBSD variant
    elif grep -qE -- '(^|[[:space:]])-q([[:space:]]|$)' <<<"$help"; then
        NC_OPTS="-q 1"      # traditional / GNU variant
    else
        NC_OPTS=""          # e.g. ncat, closes on its own
    fi
}

# Runs a single test.
#   $1 name
#   $2 expected behavior
#   $@ command that produces the bytes
run_test() {
    local name="$1"
    local expected="$2"
    shift 2

    echo
    echo "=== $name"
    echo "    Expected: $expected"

    local -a nc_cmd=(nc $NC_OPTS "$HOST" "$PORT")
    if command -v timeout >/dev/null 2>&1; then
        nc_cmd=(timeout "$TIMEOUT" "${nc_cmd[@]}")
    fi

    { "$@"; sleep "$HOLD"; } | "${nc_cmd[@]}" | od -An -tx1 | sed 's/^/    Response:/'

    echo "    (connection closed)"
}

# ---------------------------------------------------------------------------
# Tests: everything at once

fast_tests() {
    echo
    echo "##### Sent at once #####"

    run_test "One frame" \
        "1 recv with 12 bytes, frame TID 1, fill level 0 afterwards" \
        send_now "$FRAME_1"

    run_test "Two frames back to back" \
        "1 recv with 24 bytes, frames TID 1 and 2, fill level 0 afterwards" \
        send_now "$FRAME_1 $FRAME_2"

    run_test "Three frames back to back" \
        "1 recv with 36 bytes, frames TID 1, 2 and 3, fill level 0 afterwards" \
        send_now "$FRAME_1 $FRAME_2 $FRAME_3"

    run_test "Two valid frames, then an invalid one" \
        "Frames TID 1 and 2 processed, then invalid frame, server closes" \
        send_now "$FRAME_1 $FRAME_2 $FRAME_BAD"
}

# ---------------------------------------------------------------------------
# Tests: in chunks with pauses

slow_tests() {
    echo
    echo "##### Sent in chunks #####"

    # 3 + 4 + 5 bytes: cut in the middle of the protocol ID and after the unit ID
    run_test "One frame in three pieces" \
        "recv with 3, 4 and 5 bytes, frame TID 1 only after the third" \
        send_chunks "00 01 00" "00 00 06 01" "03 00 00 00 0a"

    run_test "One frame byte by byte" \
        "12 recv with 1 byte each, frame TID 1 only after the last" \
        send_pieces 1 "$BYTE_DELAY" "$FRAME_1"

    # 16 + 8 bytes: frame 1 plus the first 4 bytes of frame 2
    run_test "One frame plus the start of the next" \
        "recv 16 bytes: TID 1, fill level 4. recv 8 bytes: TID 2, fill level 0" \
        send_chunks "$FRAME_1 00 02 00 00" "00 06 01 03 00 0a 00 05"

    # 17 + 7 bytes: cut in the middle of the length field of frame 2
    run_test "Cut in the middle of the length field" \
        "recv 17 bytes: TID 1, fill level 5. recv 7 bytes: TID 2, fill level 0" \
        send_chunks "$FRAME_1 00 02 00 00 00" "06 01 03 00 0a 00 05"

    # 36 bytes in chunks of 5: cuts never fall on a frame boundary
    run_test "Three frames in pieces of 5 bytes" \
        "8 recv (7 x 5 + 1 byte), frames TID 1, 2 and 3, fill level 0 at the end" \
        send_pieces 5 "$DELAY" "$FRAME_1 $FRAME_2 $FRAME_3"
}

# ---------------------------------------------------------------------------

usage() {
    echo "Usage: $0 [fast|slow|all] [host] [port]"
}

if ! command -v nc >/dev/null 2>&1; then
    echo "nc (netcat) not found." >&2
    exit 1
fi

detect_nc_opts
echo "Target: $HOST:$PORT   nc options: '${NC_OPTS}'"

case "$MODE" in
    fast) fast_tests ;;
    slow) slow_tests ;;
    all)  fast_tests; slow_tests ;;
    -h|--help) usage ;;
    *) usage; exit 1 ;;
esac
