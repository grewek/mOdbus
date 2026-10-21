#!/usr/bin/env bash
#
# Fuzzer for the Modbus TCP server. Sends invalid and malformed input and,
# after every case, checks that the server still answers a valid FC 0x03
# request correctly. The first input that breaks the server is saved and the
# run stops, because later results would not mean anything.
#
# Usage:
#   ./modbus_fuzz.sh [cases] [host] [port]
#
# Environment variables:
#   SEED      Random seed. The same seed produces the same cases  (default: random)
#   HOLD      Seconds to wait for the reply to one case          (default: 0.3)
#   TIMEOUT   Hard limit per connection in seconds                (default: 5)
#   OUT_DIR   Directory for saved failure reports                 (default: ./fuzz_failures)
#   NC_OPTS   Options for nc. Detected automatically if unset.
#
# Run this only against your own test server.
#
# Reply classes:
#   closed     no bytes, the server closed the connection (fine for broken frames)
#   exception  well-formed exception frame (function code | 0x80)
#   normal     well-formed FC 0x03 response
#   multi      several well-formed frames in one reply (TCP does not mark frame
#              boundaries, so one reply can carry several responses)
#   malformed  anything else. Saved and counted as a finding, the run continues.
#
# A failed health check (no reply or a wrong reply to a valid request) means
# the server is broken or hung. The input is saved and the run stops.
#
# Each failure report decodes the request frame by frame, lists the expected
# replies and compares them with the actual replies.

set -u

CASES="${1:-1000}"
HOST="${2:-127.0.0.1}"
PORT="${3:-10502}"
HOLD="${HOLD:-0.3}"
TIMEOUT="${TIMEOUT:-5}"
OUT_DIR="${OUT_DIR:-./fuzz_failures}"
SEED="${SEED:-$RANDOM$RANDOM}"
RANDOM="$SEED"

EDGE_U16=(0 1 2 3 4 5 119 120 121 125 126 127 253 254 255 256 4096 32767 32768 65534 65535)

CASE_HEX=""
CASE_KIND=""
CASE_REPLY=""
REPLY_HEX=""
HEALTH_REPLY=""
FRAME=()
REQUEST_NOTES=()
EXPECTED_REPLIES=()
ACTUAL_REPLIES=()
declare -A COUNTS=([closed]=0 [exception]=0 [normal]=0 [multi]=0 [malformed]=0)

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
        NC_OPTS="-N"
    elif grep -qE -- '(^|[[:space:]])-q([[:space:]]|$)' <<<"$help"; then
        NC_OPTS="-q 1"
    else
        NC_OPTS=""
    fi
}

# Random 16-bit value.
rand16() {
    echo $(( (RANDOM * 32768 + RANDOM) & 0xFFFF ))
}

# Random hex bytes, $1 = count.
random_bytes() {
    head -c "$1" /dev/urandom | od -An -tx1 -v | tr -s ' \n' ' ' | sed 's/^ //; s/ $//'
}

# Hex bytes of a 16-bit value, big-endian, e.g. 258 -> "01 02".
hex_u16() {
    printf "%02x %02x" $(( ($1 >> 8) & 0xFF )) $(( $1 & 0xFF ))
}

# Valid FC 0x03 request: transaction ID, start address, quantity (decimal).
valid_fc3_frame() {
    printf "%s 00 00 00 06 01 03 %s %s" "$(hex_u16 "$1")" "$(hex_u16 "$2")" "$(hex_u16 "$3")"
}

# Expected valid FC 0x03 response (unit ID 01). Register i contains i << 8 if
# i is even, otherwise i. Same rule as in the server's initialisation.
#   $1 transaction ID as hex bytes
#   $2 start address (decimal)
#   $3 quantity (decimal)
expected_fc3() {
    local tid="$1"
    local start="$2"
    local quantity="$3"
    local byte_count=$((quantity * 2))
    local length=$((3 + byte_count))
    local values=""
    local i value

    for ((i = 0; i < quantity; i++)); do
        value=$((start + i))
        if (( value % 2 == 0 )); then
            value=$(( value << 8 ))
        fi
        values+=$(printf " %02x %02x" $(((value >> 8) & 0xFF)) $((value & 0xFF)))
    done

    printf "%s 00 00 00 %02x 01 03 %02x%s" "$tid" "$length" "$byte_count" "$values"
}

# Sets the 16-bit value at byte offset $1 of FRAME, if it exists.
set_u16_at() {
    local hi lo
    (( $1 + 1 < ${#FRAME[@]} )) || return 0
    read -r hi lo <<<"$(hex_u16 "$2")"
    FRAME[$1]="$hi"
    FRAME[$(( $1 + 1 ))]="$lo"
}

# Applies one random mutation to FRAME.
mutate_frame() {
    local len="${#FRAME[@]}"
    local choice=$(( RANDOM % 9 ))

    case "$choice" in
        0) FRAME[RANDOM % len]="$(random_bytes 1)" ;;
        1) set_u16_at 4 "${EDGE_U16[RANDOM % ${#EDGE_U16[@]}]}" ;;
        2) set_u16_at 2 $(( 1 + RANDOM % 65535 )) ;;
        3) set_u16_at 8 "${EDGE_U16[RANDOM % ${#EDGE_U16[@]}]}" ;;
        4) set_u16_at 10 "${EDGE_U16[RANDOM % ${#EDGE_U16[@]}]}" ;;
        5) (( len > 7 )) && FRAME[7]="$(random_bytes 1)" ;;
        6) FRAME=("${FRAME[@]:0:$(( 1 + RANDOM % len ))}") ;;
        7) FRAME+=($(random_bytes $(( 1 + RANDOM % 300 )))) ;;
        8) FRAME=($(random_bytes $(( 1 + RANDOM % 12 )))) ;;
    esac
}

# Builds one input in CASE_HEX: noise, or one to three frames, some mutated.
build_case() {
    if (( RANDOM % 20 == 0 )); then
        CASE_HEX="$(random_bytes $(( 1 + RANDOM % 300 )))"
        CASE_KIND="noise"
        return
    fi

    local frames=$(( 1 + RANDOM % 3 ))
    local out=""
    local f

    for (( f = 0; f < frames; f++ )); do
        FRAME=($(valid_fc3_frame "$(rand16)" "$(rand16)" $(( RANDOM % 130 ))))
        if (( RANDOM % 2 == 0 )); then
            mutate_frame
        fi
        out+=" ${FRAME[*]}"
    done

    CASE_HEX="${out# }"
    CASE_KIND="$frames frame(s)"
}

# Sends $1 (hex bytes) and stores the reply in REPLY_HEX.
send_and_read() {
    local file
    file="$(mktemp)"

    { emit "$1"; sleep "$HOLD"; } \
        | timeout "$TIMEOUT" nc $NC_OPTS "$HOST" "$PORT" > "$file" 2>/dev/null

    REPLY_HEX="$(od -An -tx1 -v "$file" | tr -s ' \n' ' ' | sed 's/^ //; s/ $//')"
    rm -f "$file"
}

# Prints one class per frame in the reply $1, split by the MBAP length field.
# TCP does not mark frame boundaries, so the reply is split by length, not by
# packets. A trailing incomplete frame counts as malformed.
classify_frames() {
    local -a out=($1)
    local total="${#out[@]}"
    local o=0 length size fc

    while (( o < total )); do
        if (( total - o < 6 )); then
            echo malformed
            return
        fi

        length=$(( 16#${out[o+4]} * 256 + 16#${out[o+5]} ))
        size=$(( 6 + length ))

        if (( length < 2 || total - o < size )); then
            echo malformed
            return
        fi

        fc=$(( 16#${out[o+7]} ))

        if (( size == 9 && length == 3 && (fc & 0x80) )); then
            echo exception
        elif (( fc == 3 && size >= 9 && 16#${out[o+8]} == size - 9 )); then
            echo normal
        else
            echo malformed
        fi

        o=$(( o + size ))
    done
}

# Prints closed, exception, normal, multi or malformed for the reply in $1.
# multi means several well-formed frames in one reply.
classify_reply() {
    local -a lines=()
    local line

    mapfile -t lines < <(classify_frames "$1")

    if (( ${#lines[@]} == 0 )); then
        echo closed
        return
    fi

    for line in "${lines[@]}"; do
        if [ "$line" = "malformed" ]; then
            echo malformed
            return
        fi
    done

    if (( ${#lines[@]} == 1 )); then
        echo "${lines[0]}"
    else
        echo multi
    fi
}

# Returns 0 if a valid request still gets the correct reply. Keeps the reply
# in HEALTH_REPLY.
health_check() {
    local request expected
    request="$(valid_fc3_frame 65534 0 1)"
    expected="$(expected_fc3 "ff fe" 0 1)"
    send_and_read "$request"
    HEALTH_REPLY="$REPLY_HEX"
    [ "$HEALTH_REPLY" = "$expected" ]
}

# Name of a function code, for the report.
fc_name() {
    if (( $1 == 3 )); then
        echo "read holding registers"
    else
        echo "not implemented, server only knows 0x03"
    fi
}

# Adds an expected exception reply to EXPECTED_REPLIES.
#   $1 transaction ID as "hi lo"
#   $2 unit ID as hex
#   $3 function code (decimal)
#   $4 exception code (decimal)
add_expected_exception() {
    EXPECTED_REPLIES+=("$(printf '%s 00 00 00 03 %s %02x %02x' "$1" "$2" $(( $3 | 0x80 )) "$4")")
}

# Decodes CASE_HEX frame by frame into REQUEST_NOTES and EXPECTED_REPLIES.
# Stops at the first frame that the server must not process further.
analyze_input() {
    local -a in=($CASE_HEX)
    local total="${#in[@]}"
    local o=0 f=0
    local tid_hex pid length size uid_hex fc addr qty

    REQUEST_NOTES=()
    EXPECTED_REPLIES=()

    while (( o < total )); do
        f=$(( f + 1 ))

        if (( total - o < 6 )); then
            REQUEST_NOTES+=("Frame $f at offset $o: only $(( total - o )) byte(s), header incomplete.")
            REQUEST_NOTES+=("    Expected: server waits for more data, connection ends without reply.")
            break
        fi

        tid_hex="${in[o]} ${in[o+1]}"
        pid=$(( 16#${in[o+2]} * 256 + 16#${in[o+3]} ))
        length=$(( 16#${in[o+4]} * 256 + 16#${in[o+5]} ))

        REQUEST_NOTES+=("Frame $f at offset $o")
        REQUEST_NOTES+=("    Transaction ID  $tid_hex  ($(( 16#${in[o]} * 256 + 16#${in[o+1]} )))")

        if (( pid != 0 )); then
            REQUEST_NOTES+=("    Protocol ID     $pid  INVALID, must be 0")
            REQUEST_NOTES+=("    Expected: connection closed without reply. Nothing after this frame is processed.")
            break
        fi
        REQUEST_NOTES+=("    Protocol ID     0  ok")

        if (( length < 2 || length > 254 )); then
            REQUEST_NOTES+=("    Length          $length  INVALID, allowed 2..254")
            REQUEST_NOTES+=("    Expected: connection closed without reply. Nothing after this frame is processed.")
            break
        fi

        size=$(( 6 + length ))
        REQUEST_NOTES+=("    Length          $length  -> frame size $size bytes")

        if (( total - o < size )); then
            REQUEST_NOTES+=("    Only $(( total - o )) of $size bytes present.")
            REQUEST_NOTES+=("    Expected: server waits for the rest, connection ends without reply.")
            break
        fi

        uid_hex="${in[o+6]}"
        fc=$(( 16#${in[o+7]} ))
        REQUEST_NOTES+=("    Unit ID         $uid_hex")
        REQUEST_NOTES+=("    Function code   $(printf '%02x' "$fc")  ($(fc_name "$fc"))")

        if (( fc != 3 )); then
            REQUEST_NOTES+=("    Expected: exception 01 (IllegalFunction).")
            add_expected_exception "$tid_hex" "$uid_hex" "$fc" 1
        elif (( length != 6 )); then
            REQUEST_NOTES+=("    Length for FC 0x03 should be 6 (unit ID, FC, address, quantity), got $length.")
            REQUEST_NOTES+=("    Expected: exception 03 (IllegalDataValue). Proposal, not decided yet.")
            add_expected_exception "$tid_hex" "$uid_hex" "$fc" 3
        else
            addr=$(( 16#${in[o+8]} * 256 + 16#${in[o+9]} ))
            qty=$(( 16#${in[o+10]} * 256 + 16#${in[o+11]} ))
            REQUEST_NOTES+=("    Start address   $addr  (0x$(printf '%04x' "$addr"))")
            REQUEST_NOTES+=("    Quantity        $qty")

            if (( qty < 1 || qty > 125 )); then
                REQUEST_NOTES+=("    Expected: exception 03 (IllegalDataValue), quantity must be 1..125.")
                add_expected_exception "$tid_hex" "$uid_hex" "$fc" 3
            elif (( addr + qty > 120 )); then
                REQUEST_NOTES+=("    Expected: exception 02 (IllegalDataAddress), registers 0..119 exist.")
                add_expected_exception "$tid_hex" "$uid_hex" "$fc" 2
            else
                REQUEST_NOTES+=("    Expected: normal response with registers $addr..$(( addr + qty - 1 )).")
                local -a reply=($(expected_fc3 "$tid_hex" "$addr" "$qty"))
                reply[6]="$uid_hex"
                EXPECTED_REPLIES+=("${reply[*]}")
            fi
        fi

        o=$(( o + size ))
    done
}

# Splits the actual reply into frames and stores them in ACTUAL_REPLIES.
analyze_reply() {
    local -a out=($1)
    local total="${#out[@]}"
    local o=0 length size

    ACTUAL_REPLIES=()

    while (( o < total )); do
        if (( total - o < 6 )); then
            ACTUAL_REPLIES+=("${out[*]:o} (incomplete header)")
            break
        fi

        length=$(( 16#${out[o+4]} * 256 + 16#${out[o+5]} ))
        size=$(( 6 + length ))

        if (( total - o < size )); then
            ACTUAL_REPLIES+=("${out[*]:o} (incomplete frame, $(( total - o )) of $size bytes)")
            break
        fi

        ACTUAL_REPLIES+=("${out[*]:o:size}")
        o=$(( o + size ))
    done
}

# Prints the bytes in lines of BYTES_PER_LINE bytes, with offsets.
print_hex_block() {
    local -a bytes=($1)
    local count="${#bytes[@]}"
    local i

    if (( count == 0 )); then
        echo "    <none>"
        return
    fi

    for (( i = 0; i < count; i += 32 )); do
        printf "    %04x  %s\n" "$i" "${bytes[*]:i:32}"
    done
}

# Writes a full failure report.
#   $1 file
#   $2 case number
#   $3 reason
write_report() {
    local file="$1"
    local n="$2"
    local reason="$3"
    local -a sent=($CASE_HEX)
    local max i e a verdict count_diff

    analyze_input
    analyze_reply "$CASE_REPLY"

    {
        echo "Case $n (seed $SEED, kind: $CASE_KIND)"
        echo "Reason: $reason"
        echo
        echo "Sent input, ${#sent[@]} bytes:"
        print_hex_block "$CASE_HEX"
        echo
        echo "Request, decoded:"
        printf "    %s\n" "${REQUEST_NOTES[@]}"
        echo
        echo "Replies, expected vs actual:"

        max="${#EXPECTED_REPLIES[@]}"
        if (( ${#ACTUAL_REPLIES[@]} > max )); then
            max="${#ACTUAL_REPLIES[@]}"
        fi

        if (( max == 0 )); then
            echo "    none expected, none received"
        fi

        for (( i = 0; i < max; i++ )); do
            e="${EXPECTED_REPLIES[i]:-<none>}"
            a="${ACTUAL_REPLIES[i]:-<none>}"
            if [ "$e" = "$a" ]; then
                verdict="OK"
            else
                verdict="DIFFERS"
            fi
            echo "    reply $(( i + 1 ))  $verdict"
            echo "      expected  $e"
            echo "      actual    $a"
        done

        if (( ${#EXPECTED_REPLIES[@]} != ${#ACTUAL_REPLIES[@]} )); then
            echo "    count: expected ${#EXPECTED_REPLIES[@]} reply/replies, received ${#ACTUAL_REPLIES[@]}"
        fi

        echo
        echo "Health check after this case:"
        echo "    expected  $(expected_fc3 "ff fe" 0 1)"
        echo "    actual    ${HEALTH_REPLY:-<none>}"
        echo
        echo "Raw reply, ${#ACTUAL_REPLIES[@]} frame(s):"
        print_hex_block "$CASE_REPLY"
    } > "$file"
}

# Saves the failure report for the current case.
#   $1 case number
#   $2 reason
save_case() {
    local file="$OUT_DIR/case_$1.txt"
    write_report "$file" "$1" "$2"
    echo "    saved: $file"
}

if ! command -v nc >/dev/null 2>&1; then
    echo "nc (netcat) not found." >&2
    exit 1
fi

detect_nc_opts
mkdir -p "$OUT_DIR"

echo "Target: $HOST:$PORT   cases: $CASES   seed: $SEED   nc options: '${NC_OPTS}'"

health_failed=0

for (( n = 1; n <= CASES; n++ )); do
    build_case
    send_and_read "$CASE_HEX"
    CASE_REPLY="$REPLY_HEX"
    class="$(classify_reply "$CASE_REPLY")"
    COUNTS[$class]=$(( COUNTS[$class] + 1 ))

    printf "case %6d  %-16s  reply: %s\n" "$n" "$CASE_KIND" "$class"

    reason=""
    if [ "$class" = "malformed" ]; then
        reason="reply is neither closed, exception nor normal. "
    fi

    if ! health_check; then
        reason+="health check failed after this input"
        echo "    health check failed after this case: server hung, crashed or answers wrongly"
        save_case "$n" "$reason"
        health_failed=1
        break
    fi

    if [ -n "$reason" ]; then
        save_case "$n" "$reason"
    fi
done

echo
echo "Summary (seed $SEED):"
echo "    closed:    ${COUNTS[closed]}"
echo "    exception: ${COUNTS[exception]}"
echo "    normal:    ${COUNTS[normal]}"
echo "    multi:     ${COUNTS[multi]}   (several well-formed frames in one reply)"
echo "    malformed: ${COUNTS[malformed]}"
if (( health_failed )); then
    echo "    Run stopped early: health check failed. See $OUT_DIR"
fi

[ "$health_failed" -eq 0 ] && [ "${COUNTS[malformed]}" -eq 0 ]
