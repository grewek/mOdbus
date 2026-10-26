#!/usr/bin/env bash
#
# Checks Read Holding Registers (FC 0x03) and Write Single Register (FC 0x06)
# of the Modbus TCP server. Each case opens its own connection and compares
# the complete response with the expected bytes.
#
# Usage:
#   ./modbus_fc3_test.sh [fast|slow|pipelined|all] [host] [port]
#
#   fast  Each request is sent at once.
#   slow  Each request is sent in pieces of 5 bytes with pauses in between.
#   pipelined  PIPE_COUNT requests in one send. Every response must arrive,
#              in order and with the right content.
#   all   fast, slow and pipelined, one after the other (default).
#
# FC 0x06 cases run in fast and slow mode, after the FC 0x03 cases of that
# mode. Pipelined mode covers FC 0x03 only.
#
# Environment variables:
#   DELAY    Pause between pieces in seconds for slow mode   (default: 1)
#   HOLD     Seconds the connection stays open after sending (default: 2)
#   TIMEOUT    Hard upper limit per case in seconds           (default: 10)
#   DIFF_LINES Maximum rows shown in a failure diff           (default: 20)
#   BYTES_PER_LINE  Bytes per line in the hex output          (default: 32)
#   PIPE_COUNT      Requests sent at once in pipelined mode   (default: 80)
#   NC_OPTS    Options for nc. Detected automatically if unset.
#
# Assumption: the store is initialised like this in main:
#   even register i  ->  i << 8    (high byte = i, low byte = 00)
#   odd register i   ->  i         (high byte = 00, low byte = i)
# Big-endian is visible in both kinds: a byte-swapped server would send
# 00 hi for even registers and lo 00 for odd ones.
#
# Valid response format:
#   MBAP header (same transaction ID, protocol ID 0, length 3 + 2*quantity,
#   same unit ID), function code 0x03, byte count 2*quantity, then the
#   values big-endian.
#
# Out-of-range requests get exception 0x02 (IllegalDataAddress):
#   FC 0x03, address 0,      quantity 125   -> FC 0x83, exception 0x02
#   FC 0x03, address 119,    quantity 2     -> FC 0x83, exception 0x02
#   FC 0x03, address 120,    quantity 1     -> FC 0x83, exception 0x02
#   FC 0x03, address 0xFFFF, quantity 2     -> FC 0x83, exception 0x02
#
# Write Single Register (FC 0x06) echoes the request on success:
#   FC 0x06, address A, value V             -> same bytes back
# Out-of-range address (120 and up) gets exception 0x02:
#   FC 0x06, address 120,    value 1        -> FC 0x86, exception 0x02
#   FC 0x06, address 0xFFFF, value 1        -> FC 0x86, exception 0x02
#
# A valid write changes the store. Each write is read back with FC 0x03 and
# then restored to its original value. If a run is stopped in between,
# restart the server so the store is initialised again.

set -u

MODE="${1:-all}"
HOST="${2:-127.0.0.1}"
PORT="${3:-10502}"
DELAY="${DELAY:-1}"
HOLD="${HOLD:-2}"
TIMEOUT="${TIMEOUT:-10}"
DIFF_LINES="${DIFF_LINES:-20}"
BYTES_PER_LINE="${BYTES_PER_LINE:-32}"
PIPE_COUNT="${PIPE_COUNT:-80}"

PASSED=0
FAILED=0
SEND_STYLE="fast"
NEXT_TID=64      # transaction IDs for FC 0x06 cases start at 0x0040
TID_HEX=""

# Writes hex bytes like "00 01 0a" as raw bytes.
emit() {
    local out=""
    local b
    for b in $1; do
        out+="\\x$b"
    done
    printf "$out"
}

# Splits the bytes into pieces of a fixed size and sends them with a pause.
#   $1 piece size in bytes
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

# Sends one request in the style selected by SEND_STYLE.
#   $1 request as hex bytes
send_request() {
    if [ "$SEND_STYLE" = "slow" ]; then
        send_pieces 5 "$DELAY" "$1"
    else
        emit "$1"
    fi
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

# Value of the register with absolute address $1, as set up in main.
register_value() {
    if (( $1 % 2 == 0 )); then
        echo $(( $1 << 8 ))
    else
        echo $(( $1 ))
    fi
}

# Builds the expected valid FC 0x03 response for registers start .. start+quantity-1.
#   $1 transaction ID as hex bytes, e.g. "00 04"
#   $2 start address as decimal number
#   $3 quantity as decimal number
expected_fc3() {
    local tid="$1"
    local start="$2"
    local quantity="$3"
    local byte_count=$((quantity * 2))
    local length=$((3 + byte_count))
    local values=""
    local i value

    for ((i = 0; i < quantity; i++)); do
        value=$(register_value $((start + i)))
        values+=$(printf " %02x %02x" $(((value >> 8) & 0xFF)) $((value & 0xFF)))
    done

    printf "%s 00 00 00 %02x 01 03 %02x%s" "$tid" "$length" "$byte_count" "$values"
}

# Name of the frame field at byte offset $1.
#   $2 1 if the expected response is an exception, otherwise 0
field_name() {
    local i="$1"
    local exception="$2"

    case "$i" in
        0|1) echo "transaction id" ;;
        2|3) echo "protocol id" ;;
        4|5) echo "length" ;;
        6)   echo "unit id" ;;
        7)   echo "function code" ;;
        8)
            if [ "$exception" -eq 1 ]; then
                echo "exception code"
            else
                echo "byte count"
            fi
            ;;
        *)
            if [ "$exception" -eq 1 ]; then
                echo "(unexpected byte)"
            elif (( (i - 9) % 2 == 0 )); then
                echo "value $(( (i - 9) / 2 )) high"
            else
                echo "value $(( (i - 9) / 2 )) low"
            fi
            ;;
    esac
}

# Prints the bytes of expected and actual response side by side.
# Rows where the bytes differ are marked with "<". Output is capped at
# DIFF_LINES rows, so a long response still shows the first mismatches.
#   $1 expected response as hex bytes
#   $2 actual response as hex bytes
show_diff() {
    local -a exp_bytes=($1)
    local -a act_bytes=($2)
    local max="${#exp_bytes[@]}"
    local i e a field mark exception=0
    local shown=0
    local mismatches=0
    local first=""

    if (( ${#act_bytes[@]} > max )); then
        max="${#act_bytes[@]}"
    fi

    if [ -n "${exp_bytes[7]:-}" ] && (( 16#${exp_bytes[7]} & 0x80 )); then
        exception=1
    fi

    echo "    Length: expected ${#exp_bytes[@]} bytes, actual ${#act_bytes[@]} bytes"
    echo "    Diff:"
    printf "      %-6s %-18s %-6s %-6s\n" "offset" "field" "expect" "actual"

    for (( i = 0; i < max; i++ )); do
        e="${exp_bytes[i]:---}"
        a="${act_bytes[i]:---}"
        field="$(field_name "$i" "$exception")"

        if [ "$e" = "$a" ]; then
            mark=" "
        else
            mark="<"
            mismatches=$((mismatches + 1))
            if [ -z "$first" ]; then
                first="$i"
            fi
        fi

        if [ "$mark" = "<" ]; then
            if (( shown < DIFF_LINES )); then
                printf "    %s %-6s %-18s %-6s %-6s\n" "$mark" "$i" "$field" "$e" "$a"
                shown=$((shown + 1))
            fi
        elif (( i < 9 )); then
            printf "    %s %-6s %-18s %-6s %-6s\n" "$mark" "$i" "$field" "$e" "$a"
        fi
    done

    if [ "$mismatches" -eq 0 ]; then
        echo "    No differing bytes (lengths may still differ, see above)."
    else
        echo "    $mismatches byte(s) differ, first at offset $first."
        if (( mismatches > shown )); then
            echo "    ... $((mismatches - shown)) more not shown (raise DIFF_LINES to see them)."
        fi
    fi
}

# Prints hex bytes in lines of at most BYTES_PER_LINE bytes. Each line starts
# with the offset of its first byte. The label is printed on the first line.
#   $1 label
#   $2 hex bytes
print_hex() {
    local label="$1"
    local -a bytes=($2)
    local count="${#bytes[@]}"
    local i

    if (( count == 0 )); then
        printf "    %-9s <none>\n" "$label"
        return
    fi

    for (( i = 0; i < count; i += BYTES_PER_LINE )); do
        if (( i == 0 )); then
            printf "    %-9s %04x  %s\n" "$label" "$i" "${bytes[*]:i:BYTES_PER_LINE}"
        else
            printf "    %-9s %04x  %s\n" "" "$i" "${bytes[*]:i:BYTES_PER_LINE}"
        fi
    done
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

    { send_request "$request"; sleep "$HOLD"; } \
        | timeout "$TIMEOUT" nc $NC_OPTS "$HOST" "$PORT" > "$response_file"

    actual="$(od -An -tx1 -v "$response_file" | tr -s ' \n' ' ' | sed 's/^ //; s/ $//')"
    rm -f "$response_file"

    echo
    echo "=== [$SEND_STYLE] $name"
    print_hex "Request:" "$request"
    print_hex "Expected:" "$expected"
    if [ -n "$actual" ]; then
        print_hex "Actual:" "$actual"
    else
        echo "    Actual:   <no response>"
    fi

    if [ "$actual" = "$expected" ]; then
        echo "    PASS"
        PASSED=$((PASSED + 1))
    else
        echo "    FAIL"
        if [ -z "$actual" ]; then
            echo "    No response to compare."
        else
            show_diff "$expected" "$actual"
        fi
        FAILED=$((FAILED + 1))
    fi
}

# Two bytes, big-endian, as hex, e.g. 4660 -> "12 34".
hex16() {
    printf "%02x %02x" $(( ($1 >> 8) & 0xFF )) $(( $1 & 0xFF ))
}

# Value as 0x-prefixed hex for display, e.g. 4660 -> "0x1234".
hexval() {
    printf "0x%04X" "$1"
}

# Sets TID_HEX to the next transaction ID and counts up.
# Does not run in a subshell, so the counter survives.
next_tid() {
    TID_HEX="$(printf "%02x %02x" $(( (NEXT_TID >> 8) & 0xFF )) $(( NEXT_TID & 0xFF )))"
    NEXT_TID=$(( NEXT_TID + 1 ))
}

# Builds a valid FC 0x03 response from explicit values.
#   $1 transaction ID as hex bytes, e.g. "00 40"
#   $2... values as decimal numbers, one per register
fc3_response_values() {
    local tid="$1"
    shift
    local count=$#
    local values=""
    local v

    for v in "$@"; do
        values+=" $(hex16 "$v")"
    done

    printf "%s 00 00 00 %02x 01 03 %02x%s" "$tid" $(( 3 + 2 * count )) $(( 2 * count )) "$values"
}

# Writes value to addr, reads back registers from read_start, then restores
# the original value. Each step is its own connection with its own ID.
#   $1 address
#   $2 value (decimal)
#   $3 start of the read-back
#   $4 number of registers to read back
write_and_verify() {
    local addr="$1"
    local value="$2"
    local read_start="$3"
    local read_qty="$4"
    local original
    local -a expected_values=()
    local i a

    original="$(register_value "$addr")"

    next_tid
    run_case "FC6 write address $addr = $(hexval "$value")" \
        "$TID_HEX 00 00 00 06 01 06 $(hex16 "$addr") $(hex16 "$value")" \
        "$TID_HEX 00 00 00 06 01 06 $(hex16 "$addr") $(hex16 "$value")"

    for (( i = 0; i < read_qty; i++ )); do
        a=$(( read_start + i ))
        if (( a == addr )); then
            expected_values+=("$value")
        else
            expected_values+=("$(register_value "$a")")
        fi
    done

    next_tid
    run_case "FC3 read back addresses $read_start to $(( read_start + read_qty - 1 )) after the write" \
        "$TID_HEX 00 00 00 06 01 03 $(hex16 "$read_start") $(hex16 "$read_qty")" \
        "$(fc3_response_values "$TID_HEX" "${expected_values[@]}")"

    next_tid
    run_case "FC6 restore address $addr = $(hexval "$original")" \
        "$TID_HEX 00 00 00 06 01 06 $(hex16 "$addr") $(hex16 "$original")" \
        "$TID_HEX 00 00 00 06 01 06 $(hex16 "$addr") $(hex16 "$original")"
}

# Write Single Register cases. Run after the FC 0x03 cases of the same mode.
fc6_cases() {
    # --- Valid writes, read back and restored ----------------------------
    # Each value is written and read back together with its neighbours,
    # so a write that touches the wrong register shows up.

    write_and_verify 0 4660 0 1          # 0x1234 at the first register
    write_and_verify 7 43981 6 3         # 0xABCD at an odd address, neighbours 6 and 8
    write_and_verify 119 48879 118 2     # 0xBEEF at the last register
    write_and_verify 10 23130 9 3        # 0x5A5A, neighbours 9 and 11
    write_and_verify 3 65535 2 2         # 0xFFFF, all bits set

    # --- Out-of-range addresses -------------------------------------------

    next_tid
    run_case "FC6, address 120 (first address past end)" \
        "$TID_HEX 00 00 00 06 01 06 00 78 00 01" \
        "$TID_HEX 00 00 00 03 01 86 02"

    next_tid
    run_case "FC6, address 0xFFFF" \
        "$TID_HEX 00 00 00 06 01 06 ff ff 00 01" \
        "$TID_HEX 00 00 00 03 01 86 02"

    # A rejected write must not change anything. Registers 118 and 119 are read back.
    next_tid
    run_case "FC3 after the rejected writes, addresses 118 and 119 unchanged" \
        "$TID_HEX 00 00 00 06 01 03 00 76 00 02" \
        "$(fc3_response_values "$TID_HEX" "$(register_value 118)" "$(register_value 119)")"
}

# All cases, run once per send style.
fc3_cases() {
    # --- Valid requests ---------------------------------------------------

    run_case "FC3, address 0, quantity 1" \
        "00 04 00 00 00 06 01 03 00 00 00 01" \
        "$(expected_fc3 "00 04" 0 1)"

    run_case "FC3, address 10, quantity 5" \
        "00 05 00 00 00 06 01 03 00 0a 00 05" \
        "$(expected_fc3 "00 05" 10 5)"

    run_case "FC3, address 119 (last register), quantity 1" \
        "00 06 00 00 00 06 01 03 00 77 00 01" \
        "$(expected_fc3 "00 06" 119 1)"

    run_case "FC3, address 0, quantity 120 (whole store)" \
        "00 07 00 00 00 06 01 03 00 00 00 78" \
        "$(expected_fc3 "00 07" 0 120)"

    # --- Out-of-range requests --------------------------------------------

    run_case "FC3, address 0, quantity 125 (larger than store)" \
        "00 08 00 00 00 06 01 03 00 00 00 7d" \
        "00 08 00 00 00 03 01 83 02"

    run_case "FC3, address 119, quantity 2 (runs past end)" \
        "00 09 00 00 00 06 01 03 00 77 00 02" \
        "00 09 00 00 00 03 01 83 02"

    run_case "FC3, address 120 (first address past end), quantity 1" \
        "00 0b 00 00 00 06 01 03 00 78 00 01" \
        "00 0b 00 00 00 03 01 83 02"

    run_case "FC3, address 0xFFFF, quantity 2 (sum overflows u16)" \
        "00 0a 00 00 00 06 01 03 ff ff 00 02" \
        "00 0a 00 00 00 03 01 83 02"
}

# Sends PIPE_COUNT FC 0x03 requests in one send. Request i has transaction ID i
# and reads one register, so every response is 11 bytes long. All responses
# must arrive, in order, with the right content.
pipelined_case() {
    local count="$PIPE_COUNT"
    local request_stream=""
    local -a expected_chunks=()
    local -a actual_bytes=()
    local -a seen_order=()
    local -A received=()
    local i addr tid_hex addr_hex response_file
    local total responses leftover k start tid_num chunk
    local missing="" mismatched="" unexpected="" order_problem=""
    local first_bad_id="" first_bad_chunk=""

    for (( i = 1; i <= count; i++ )); do
        addr=$(( (i - 1) % 120 ))
        tid_hex="$(printf "%02x %02x" $(( (i >> 8) & 0xFF )) $(( i & 0xFF )))"
        addr_hex="$(printf "%02x %02x" $(( (addr >> 8) & 0xFF )) $(( addr & 0xFF )))"
        request_stream+="$tid_hex 00 00 00 06 01 03 $addr_hex 00 01 "
        expected_chunks[i]="$(expected_fc3 "$tid_hex" "$addr" 1)"
    done

    response_file="$(mktemp)"

    { emit "$request_stream"; sleep "$HOLD"; } \
        | timeout "$TIMEOUT" nc $NC_OPTS "$HOST" "$PORT" > "$response_file"

    actual_bytes=($(od -An -tx1 -v "$response_file"))
    rm -f "$response_file"

    total="${#actual_bytes[@]}"
    responses=$(( total / 11 ))
    leftover=$(( total % 11 ))

    for (( k = 0; k < responses; k++ )); do
        start=$(( k * 11 ))
        tid_num=$(( 16#${actual_bytes[start]} * 256 + 16#${actual_bytes[start + 1]} ))
        seen_order+=("$tid_num")

        if (( tid_num < 1 || tid_num > count )); then
            unexpected+=" $tid_num"
            continue
        fi

        received[$tid_num]=1
        chunk="${actual_bytes[*]:start:11}"
        if [ "$chunk" != "${expected_chunks[tid_num]}" ]; then
            mismatched+=" $tid_num"
            if [ -z "$first_bad_id" ]; then
                first_bad_id="$tid_num"
                first_bad_chunk="$chunk"
            fi
        fi
    done

    for (( i = 1; i <= count; i++ )); do
        if [ -z "${received[$i]:-}" ]; then
            missing+=" $i"
        fi
    done

    for (( k = 0; k < ${#seen_order[@]}; k++ )); do
        if [ "${seen_order[k]}" -ne $(( k + 1 )) ]; then
            order_problem="position $(( k + 1 )) carried ID ${seen_order[k]}"
            break
        fi
    done

    echo
    echo "=== [pipelined] $count requests in one send"
    if [ "$total" -eq 0 ]; then
        echo "    No response at all."
    fi
    echo "    Responses received: $responses of $count, leftover bytes: $leftover"
    echo "    Missing IDs:    ${missing:-none}"
    echo "    Wrong content:  ${mismatched:-none}"
    echo "    Unexpected IDs: ${unexpected:-none}"
    if [ -n "$missing" ] && [ -n "$order_problem" ]; then
        order_problem="shifted, caused by missing IDs"
    fi
    echo "    Order:          ${order_problem:-in order}"

    if [ "$total" -gt 0 ] && [ -z "$missing" ] && [ -z "$mismatched" ] \
        && [ -z "$unexpected" ] && [ -z "$order_problem" ] \
        && [ "$leftover" -eq 0 ] && [ "$responses" -eq "$count" ]; then
        echo "    PASS"
        PASSED=$((PASSED + 1))
    else
        echo "    FAIL"
        if [ -n "$first_bad_id" ]; then
            echo "    First wrong response, ID $first_bad_id:"
            show_diff "${expected_chunks[first_bad_id]}" "$first_bad_chunk"
        fi
        FAILED=$((FAILED + 1))
    fi
}

usage() {
    echo "Usage: $0 [fast|slow|pipelined|all] [host] [port]"
}

if ! command -v nc >/dev/null 2>&1; then
    echo "nc (netcat) not found." >&2
    exit 1
fi

detect_nc_opts
echo "Target: $HOST:$PORT   nc options: '${NC_OPTS}'"

case "$MODE" in
    fast)
        SEND_STYLE="fast"
        echo; echo "##### Sent at once #####"
        fc3_cases
        fc6_cases
        ;;
    slow)
        SEND_STYLE="slow"
        echo; echo "##### Sent in pieces #####"
        fc3_cases
        fc6_cases
        ;;
    pipelined)
        echo; echo "##### Pipelined #####"
        pipelined_case
        ;;
    all)
        SEND_STYLE="fast"
        echo; echo "##### Sent at once #####"
        fc3_cases
        fc6_cases
        SEND_STYLE="slow"
        echo; echo "##### Sent in pieces #####"
        fc3_cases
        fc6_cases
        echo; echo "##### Pipelined #####"
        pipelined_case
        ;;
    -h|--help)
        usage
        exit 0
        ;;
    *)
        usage
        exit 1
        ;;
esac

echo
echo "Passed: $PASSED   Failed: $FAILED"

[ "$FAILED" -eq 0 ]
