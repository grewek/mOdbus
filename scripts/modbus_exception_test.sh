#!/usr/bin/env bash
#
# Checks that the server answers invalid requests with Modbus exception
# responses. Each case opens its own connection and compares the complete
# response with the expected bytes.
#
# Usage:
#   ./modbus_exception_test.sh [host] [port]
#
# Environment variables:
#   HOLD     Seconds the connection stays open after sending  (default: 2)
#   TIMEOUT  Hard upper limit per case in seconds             (default: 10)
#   NC_OPTS  Options for nc. Detected automatically if unset.
#
# Exception response format:
#   MBAP header (same transaction ID, protocol ID 0, length 3, same unit ID)
#   followed by the function code | 0x80 and the exception code.
#
#   Request                                 Expected exception
#   FC 0x03, quantity 0x7E (above 125)   -> FC 0x83, exception 0x03
#   FC 0x03, quantity 0 (below 1)        -> FC 0x83, exception 0x03
#   FC 0x06 (not implemented)            -> FC 0x86, exception 0x01

set -u

HOST="${1:-127.0.0.1}"
PORT="${2:-10502}"
HOLD="${HOLD:-2}"
TIMEOUT="${TIMEOUT:-10}"

PASSED=0
FAILED=0

# Writes hex bytes like "00 01 0a" as raw bytes.
emit() {
    local out=""
    local b
    for b in $1; do
        out+="\\x$b"
    done
    printf "$out"
}

# Detects which option makes nc close the connection once its input ends.
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

# Runs one case.
#   $1 name
#   $2 request as hex bytes
#   $3 expected response as hex bytes
run_case() {
    local name="$1"
    local request="$2"
    local expected="$3"
    local response_file
    local actual

    response_file="$(mktemp)"

    { emit "$request"; sleep "$HOLD"; } \
        | timeout "$TIMEOUT" nc $NC_OPTS "$HOST" "$PORT" > "$response_file"

    actual="$(od -An -tx1 -v "$response_file" | tr -s ' \n' ' ' | sed 's/^ //; s/ $//')"
    rm -f "$response_file"

    echo
    echo "=== $name"
    echo "    Request:  $request"
    echo "    Expected: $expected"
    echo "    Actual:   ${actual:-<no response>}"

    if [ "$actual" = "$expected" ]; then
        echo "    PASS"
        PASSED=$((PASSED + 1))
    else
        echo "    FAIL"
        FAILED=$((FAILED + 1))
    fi
}

if ! command -v nc >/dev/null 2>&1; then
    echo "nc (netcat) not found." >&2
    exit 1
fi

detect_nc_opts
echo "Target: $HOST:$PORT   nc options: '${NC_OPTS}'"

run_case "Read Holding Registers, quantity 0x7E (above maximum)" \
    "00 01 00 00 00 06 01 03 00 00 00 7e" \
    "00 01 00 00 00 03 01 83 03"

run_case "Read Holding Registers, quantity 0 (below minimum)" \
    "00 02 00 00 00 06 01 03 00 00 00 00" \
    "00 02 00 00 00 03 01 83 03"

run_case "Unknown function code 0x06" \
    "00 03 00 00 00 06 01 06 00 00 00 01" \
    "00 03 00 00 00 03 01 86 01"

echo
echo "Passed: $PASSED   Failed: $FAILED"

[ "$FAILED" -eq 0 ]
