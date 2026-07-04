#!/usr/bin/env bash
# asn_ip_lookup.sh — Extract IP ranges for Autonomous Systems via RADB whois
# Version: 0.2.0
#
# Usage: asn_ip_lookup.sh [-i FILE] [-o FILE] [-6] [-r] [-s|-S] [-v|-q] [-h] [ASN...]
#
# Examples:
#   ./asn_ip_lookup.sh AS1234
#   ./asn_ip_lookup.sh -i asns.txt -o ranges.txt -v
#   ./asn_ip_lookup.sh -6 AS1234 AS5678
#   ./asn_ip_lookup.sh -r 8.8.8.8

set -euo pipefail

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
readonly WHOIS_HOST="whois.radb.net"
readonly MAX_ASN=4294967295

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
INPUT_FILE=""
OUTPUT_FILE=""
IPV6=false
REVERSE=false
SORT=true
VERBOSE=false
QUIET=false

# ---------------------------------------------------------------------------
# Color helpers (written to stderr only)
# ---------------------------------------------------------------------------
_color_supported() {
    [ -t 2 ] && command -v tput >/dev/null 2>&1
}

log_info() {
    "$QUIET" && return 0
    if "$VERBOSE"; then
        if _color_supported; then
            printf '\033[0;32m[INFO]\033[0m  %s\n' "$*" >&2
        else
            printf '[INFO]  %s\n' "$*" >&2
        fi
    fi
}

log_warn() {
    "$QUIET" && return 0
    if _color_supported; then
        printf '\033[0;33m[WARN]\033[0m  %s\n' "$*" >&2
    else
        printf '[WARN]  %s\n' "$*" >&2
    fi
}

log_error() {
    "$QUIET" && return 0
    if _color_supported; then
        printf '\033[0;31m[ERROR]\033[0m %s\n' "$*" >&2
    else
        printf '[ERROR] %s\n' "$*" >&2
    fi
}

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------
usage() {
    cat <<'EOF'
Usage: asn_ip_lookup.sh [-i FILE] [-o FILE] [-6] [-r] [-S] [-v|-q] [-h] [ASN...]

Extract IP ranges allocated to Autonomous Systems via RADB whois.

Options:
  -i FILE   Read ASNs (or IPs in reverse mode) from FILE, one per line
  -o FILE   Write results to FILE instead of stdout
  -6        Also extract IPv6 ranges (forward lookup only)
  -r        Reverse lookup: input is IPs/CIDRs, output is originating ASN(s)
  -S        Disable sort and deduplication of output (default: sort+dedup on)
  -v        Verbose — colorized [INFO]/[WARN]/[ERROR] progress to stderr
  -q        Quiet — suppress all stderr output
  -h        Print this help and exit 0

Exit codes:
  0   Success
  1   Usage / argument error
  2   Lookup error (whois failed)

Examples:
  asn_ip_lookup.sh AS1234
  asn_ip_lookup.sh AS1234 AS5678
  asn_ip_lookup.sh -i asns.txt -o ranges.txt -v
  asn_ip_lookup.sh -6 AS1234 AS5678
  asn_ip_lookup.sh -r 8.8.8.8
  asn_ip_lookup.sh -r -i ips.txt
EOF
}

# ---------------------------------------------------------------------------
# ASN normalisation: strip AS/as prefix, validate numeric range
# Returns the bare number, or prints a warning and returns empty string
# ---------------------------------------------------------------------------
normalise_asn() {
    local raw="$1"
    local num

    # Strip leading AS/as (case-insensitive)
    num="${raw#[Aa][Ss]}"

    # Must be purely numeric
    case "$num" in
        ''|*[!0-9]*)
            log_warn "Skipping invalid ASN: '$raw'"
            return 1
            ;;
    esac

    if [ "$num" -eq 0 ]; then
        log_warn "ASN 0 is reserved, results may be empty: '$raw'"
    elif [ "$num" -gt "$MAX_ASN" ]; then
        log_warn "ASN $num exceeds RFC maximum ($MAX_ASN): '$raw'"
    fi

    printf '%s' "$num"
}

# ---------------------------------------------------------------------------
# Forward lookup: emit IPv4 (and optionally IPv6) ranges for one ASN number
# ---------------------------------------------------------------------------
forward_lookup() {
    local asn_num="$1"
    local whois_out

    log_info "Querying whois for AS${asn_num} ..."

    if ! whois_out="$(whois -h "$WHOIS_HOST" -i origin "AS${asn_num}" 2>/dev/null)"; then
        log_error "whois failed for AS${asn_num}"
        return 2
    fi

    # IPv4
    printf '%s\n' "$whois_out" \
        | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}\b'

    # IPv6
    if "$IPV6"; then
        printf '%s\n' "$whois_out" \
            | grep -oE '([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}/[0-9]{1,3}' || true
    fi
}

# ---------------------------------------------------------------------------
# Reverse lookup: emit originating ASN(s) for one IP/CIDR
# ---------------------------------------------------------------------------
reverse_lookup() {
    local ip="$1"
    local whois_out

    log_info "Reverse querying whois for $ip ..."

    if ! whois_out="$(whois -h "$WHOIS_HOST" -T route "$ip" 2>/dev/null)"; then
        log_error "whois failed for $ip"
        return 2
    fi

    printf '%s\n' "$whois_out" \
        | grep -i '^origin:' \
        | grep -oE 'AS[0-9]+'
}

# ---------------------------------------------------------------------------
# Parse flags
# ---------------------------------------------------------------------------
while getopts ':i:o:6rSvqh' opt; do
    case "$opt" in
        i) INPUT_FILE="$OPTARG" ;;
        o) OUTPUT_FILE="$OPTARG" ;;
        6) IPV6=true ;;
        r) REVERSE=true ;;
        S) SORT=false ;;
        v) VERBOSE=true ;;
        q) QUIET=true ;;
        h) usage; exit 0 ;;
        :) log_error "Option -$OPTARG requires an argument"; usage >&2; exit 1 ;;
        ?) log_error "Unknown option: -$OPTARG"; usage >&2; exit 1 ;;
    esac
done
shift $((OPTIND - 1))

# Validate conflicting flags
if "$VERBOSE" && "$QUIET"; then
    log_error "-v and -q are mutually exclusive"
    exit 1
fi

# ---------------------------------------------------------------------------
# Build the list of targets (ASNs or IPs)
# ---------------------------------------------------------------------------
targets=()

# From input file
if [ -n "$INPUT_FILE" ]; then
    if [ ! -r "$INPUT_FILE" ]; then
        log_error "Input file not found: '$INPUT_FILE'"
        exit 1
    fi
    while IFS= read -r line || [ -n "$line" ]; do
        # Skip blank lines and comments
        case "$line" in
            ''|'#'*) continue ;;
        esac
        targets+=("$line")
    done < "$INPUT_FILE"
fi

# From positional args (backward-compatible)
for arg in "$@"; do
    targets+=("$arg")
done

if [ "${#targets[@]}" -eq 0 ]; then
    log_error "No targets provided. Use -i FILE or pass ASNs as arguments."
    usage >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Run lookups; collect all output
# ---------------------------------------------------------------------------
lookup_error=0
all_results=()
skipped_count=0

for target in "${targets[@]}"; do
    if "$REVERSE"; then
        result="$(reverse_lookup "$target")" || { lookup_error=2; continue; }
    else
        asn_num="$(normalise_asn "$target")" || { skipped_count=$((skipped_count + 1)); continue; }
        result="$(forward_lookup "$asn_num")" || { lookup_error=2; continue; }
    fi

    if [ -n "$result" ]; then
        while IFS= read -r line; do
            [ -n "$line" ] && all_results+=("$line")
        done <<< "$result"
    else
        log_warn "No results for target: $target"
    fi
done

# Exit 1 if all targets were invalid and produced no results
if [ "${#all_results[@]}" -eq 0 ] && [ "$skipped_count" -eq "${#targets[@]}" ] && [ "$lookup_error" -eq 0 ]; then
    exit 1
fi

# ---------------------------------------------------------------------------
# Sort/dedup and emit
# ---------------------------------------------------------------------------
emit_results() {
    local line
    for line in "${all_results[@]+"${all_results[@]}"}"; do
        printf '%s\n' "$line"
    done
}

if "$SORT"; then
    output="$(emit_results | sort -u)"
else
    output="$(emit_results)"
fi

if [ -n "$OUTPUT_FILE" ]; then
    printf '%s\n' "$output" > "$OUTPUT_FILE"
    log_info "Results written to: $OUTPUT_FILE"
else
    [ -n "$output" ] && printf '%s\n' "$output"
fi

exit "$lookup_error"
