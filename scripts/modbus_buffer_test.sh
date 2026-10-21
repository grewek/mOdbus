#!/usr/bin/env bash
# Sendet absichtlich auffällige Daten an den Modbus-Server, um den Puffer zu prüfen.
#
# Aufruf:
#   bash modbus_buffer_test.sh garbage
#   bash modbus_buffer_test.sh pipelined [anzahl]
#
# Benötigt: bash, nc (netcat), timeout, od, awk

set -u

HOST="127.0.0.1"
PORT="10502"
MODE="${1:-pipelined}"
COUNT="${2:-43}"

# Teil der FC3-Anfrage nach der Transaktions-ID:
# Protocol-ID (2) + Length (2) + Unit-ID (1) + Funktionscode (1) + Startadresse (2) + Anzahl (2)
FC3_REST='\x00\x00\x00\x06\x01\x03\x00\x00\x00\x01'

if ! command -v nc >/dev/null 2>&1; then
  echo "nc (netcat) nicht gefunden" >&2
  exit 1
fi

# Meldungen gehen nach stderr, damit sie nicht an den Server gesendet werden.
case "$MODE" in
  garbage)
    echo "Sende 600 zufällige Bytes an $HOST:$PORT" >&2
    SENDER() { head -c 600 /dev/urandom; }
    ;;
  pipelined)
    echo "Sende $COUNT FC3-Anfragen direkt hintereinander mit IDs 1..$COUNT" >&2
    SENDER() {
      local i hi lo
      for ((i = 1; i <= COUNT; i++)); do
        hi=$(( (i >> 8) & 0xFF ))
        lo=$(( i & 0xFF ))
        # Erst die Transaktions-ID als Escape-Text bauen, dann mit dem Rest ausgeben
        printf "$(printf '\\x%02x\\x%02x' "$hi" "$lo")$FC3_REST"
      done
    }
    ;;
  *)
    echo "Unbekannter Modus: $MODE (erlaubt: garbage, pipelined)" >&2
    exit 1
    ;;
esac

# Jede Antwort auf eine FC3-Anfrage mit einem Register ist 11 Bytes lang.
# Die ersten zwei Bytes sind die Transaktions-ID (big-endian).
ANSWERS=$(SENDER | timeout 3 nc "$HOST" "$PORT" | od -An -v -tu1 -w11 | awk '{ print $1 * 256 + $2 }')

if [ -z "$ANSWERS" ]; then
  echo "Keine Antworten vom Server empfangen." >&2
  exit 0
fi

echo "Empfangene Transaktions-IDs:" >&2
echo "$ANSWERS" | tr '\n' ' ' >&2
echo "" >&2
echo "Anzahl Antworten: $(echo "$ANSWERS" | wc -l)" >&2

if [ "$MODE" = "pipelined" ]; then
  MISSING=$(awk -v n="$COUNT" '
    { seen[$1] = 1 }
    END { for (i = 1; i <= n; i++) if (!(i in seen)) print i }
  ' <<< "$ANSWERS")
  if [ -z "$MISSING" ]; then
    echo "Alle $COUNT Anfragen wurden beantwortet." >&2
  else
    echo "Fehlende Transaktions-IDs:" >&2
    echo "$MISSING" | tr '\n' ' ' >&2
    echo "" >&2
  fi
fi
