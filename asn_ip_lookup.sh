#!/usr/bin/env bash
# asn_ip_lookup.sh — Extract IP ranges for Autonomous Systems via whois
# Version: 0.3.0
#
# Usage: asn_ip_lookup.sh [-i FILE] [-o FILE] [-6] [-r] [-S] [-s SERVER]
#                         [-d SECS] [-F FORMAT] [-A] [-v|-q] [-h] [ASN...]
#
# Examples:
#   ./asn_ip_lookup.sh AS1234
#   ./asn_ip_lookup.sh -i asns.txt -o ranges.txt -v
#   ./asn_ip_lookup.sh -6 AS1234 AS5678
#   ./asn_ip_lookup.sh -r 8.8.8.8
#   ./asn_ip_lookup.sh -s ripe -F json AS1234
#   ./asn_ip_lookup.sh -A -F nmap AS1234 AS5678
#   ./asn_ip_lookup.sh -d 0.5 -i asns.txt

set -euo pipefail

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
readonly MAX_ASN=4294967295
# Fallback chain used when primary server returns zero results (forward only)
readonly FALLBACK_SERVERS="whois.radb.net whois.ripe.net rr.arin.net"

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
WHOIS_HOST="whois.radb.net"
INPUT_FILE=""
OUTPUT_FILE=""
IPV6=false
REVERSE=false
SORT=true
VERBOSE=false
QUIET=false
DELAY="0"
FORMAT="plain"
AGGREGATE=false

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
Usage: asn_ip_lookup.sh [-i FILE] [-o FILE] [-6] [-r] [-S] [-s SERVER]
                        [-d SECS] [-F FORMAT] [-A] [-v|-q] [-h] [ASN...]

Extract IP ranges allocated to Autonomous Systems via whois.

Options:
  -i FILE     Read ASNs (or IPs in reverse mode) from FILE, one per line
  -o FILE     Write results to FILE instead of stdout
  -6          Also extract IPv6 ranges (forward lookup only)
  -r          Reverse lookup: input is IPs/CIDRs, output is originating ASN(s)
  -S          Disable sort and deduplication of output (default: sort+dedup on)
  -s SERVER   Whois server preset or raw hostname
                Presets: radb (whois.radb.net), ripe (whois.ripe.net),
                         arin (rr.arin.net), apnic (whois.apnic.net)
                Default: radb
  -d SECS     Delay between lookups in seconds (default: 0); fractional ok
  -F FORMAT   Output format: plain (default), json, csv, nmap
  -A          Aggregate/merge overlapping IPv4 CIDRs (pure bash, no ipcalc)
  -v          Verbose — colorized [INFO]/[WARN]/[ERROR] progress to stderr
  -q          Quiet — suppress all stderr output
  -h          Print this help and exit 0

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
  asn_ip_lookup.sh -s ripe AS1234
  asn_ip_lookup.sh -s whois.example.net AS1234
  asn_ip_lookup.sh -d 1.5 -i asns.txt
  asn_ip_lookup.sh -F json AS1234
  asn_ip_lookup.sh -F csv -o ranges.csv AS1234
  asn_ip_lookup.sh -A -F nmap AS1234 AS5678
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
# Accepts an optional whois host override as second argument.
# ---------------------------------------------------------------------------
forward_lookup() {
    local asn_num="$1"
    local host="${2:-$WHOIS_HOST}"
    local whois_out

    log_info "Querying whois for AS${asn_num} on ${host} ..."

    if ! whois_out="$(whois -h "$host" -i origin "AS${asn_num}" 2>/dev/null)"; then
        log_error "whois failed for AS${asn_num} on ${host}"
        return 2
    fi

    # IPv4
    printf '%s\n' "$whois_out" \
        | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}\b' || true

    # IPv6
    if "$IPV6"; then
        printf '%s\n' "$whois_out" \
            | grep -oE '([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}/[0-9]{1,3}' || true
    fi
}

# ---------------------------------------------------------------------------
# Forward lookup with auto-fallback across servers when primary returns nothing
# ---------------------------------------------------------------------------
forward_lookup_with_fallback() {
    local asn_num="$1"
    local result
    local host
    local tried_hosts

    # Try the user-configured primary server first
    result="$(forward_lookup "$asn_num" "$WHOIS_HOST")" || return 2

    if [ -n "$result" ]; then
        printf '%s\n' "$result"
        return 0
    fi

    # Primary returned nothing — try fallback chain (skip servers already tried)
    tried_hosts=" $WHOIS_HOST "
    for host in $FALLBACK_SERVERS; do
        # Skip if this host was already tried
        case "$tried_hosts" in
            *" $host "*) continue ;;
        esac
        tried_hosts="${tried_hosts}${host} "

        log_warn "No results from ${WHOIS_HOST} for AS${asn_num}, retrying on ${host} ..."
        result="$(forward_lookup "$asn_num" "$host")" || continue

        if [ -n "$result" ]; then
            printf '%s\n' "$result"
            return 0
        fi
    done

    # All servers exhausted — return empty (not an error)
    return 0
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
# aggregate_cidrs — merge overlapping/adjacent IPv4 CIDRs (pure bash)
# Reads CIDRs from stdin, writes merged CIDRs to stdout.
# Non-IPv4-CIDR lines are passed through unchanged.
# ---------------------------------------------------------------------------
aggregate_cidrs() {
    local line
    local -a cidr_list=()
    local -a passthru=()

    # Separate IPv4 CIDRs from everything else
    while IFS= read -r line || [ -n "$line" ]; do
        [ -z "$line" ] && continue
        case "$line" in
            *:*) passthru+=("$line") ;;   # IPv6 — pass through
            */*)
                # Validate it looks like an IPv4 CIDR
                if printf '%s' "$line" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$'; then
                    cidr_list+=("$line")
                else
                    passthru+=("$line")
                fi
                ;;
            *) passthru+=("$line") ;;
        esac
    done

    # Print non-IPv4 lines (pass-through)
    local pt
    for pt in "${passthru[@]+"${passthru[@]}"}"; do
        printf '%s\n' "$pt"
    done

    # Nothing to aggregate
    if [ "${#cidr_list[@]}" -eq 0 ]; then
        return 0
    fi

    # Parse each CIDR into "net_int prefix" pairs, sort numerically
    # ip_to_int: converts A.B.C.D → integer
    local -a parsed=()
    local cidr net prefix a b c d net_int

    for cidr in "${cidr_list[@]}"; do
        prefix="${cidr##*/}"
        net="${cidr%%/*}"
        IFS='.' read -r a b c d <<< "$net"
        net_int=$(( (a << 24) | (b << 16) | (c << 8) | d ))
        parsed+=("${net_int} ${prefix} ${cidr}")
    done

    # Sort by net_int (field 1) then prefix (field 2)
    local sorted_parsed
    sorted_parsed="$(printf '%s\n' "${parsed[@]}" | sort -k1,1n -k2,2n)"

    # Merge pass — merges contained subnets AND aligned sibling pairs
    local cur_net_int=-1
    local cur_prefix=-1
    local cur_end=-1

    int_to_cidr() {
        local n="$1" p="$2"
        local oc1 oc2 oc3 oc4
        oc1=$(( (n >> 24) & 255 ))
        oc2=$(( (n >> 16) & 255 ))
        oc3=$(( (n >>  8) & 255 ))
        oc4=$(( n & 255 ))
        printf '%d.%d.%d.%d/%d\n' "$oc1" "$oc2" "$oc3" "$oc4" "$p"
    }

    # _try_merge: attempts to merge current window with an adjacent sibling block.
    # Sets cur_prefix and cur_end if merge succeeds; returns 0 on merge, 1 otherwise.
    # Args: cur_net_int cur_prefix next_net_int next_prefix
    _try_merge() {
        local cni="$1" cp="$2" nni="$3" np="$4"
        # Siblings must have equal prefix lengths
        [ "$cp" -ne "$np" ] && return 1
        # current block size
        local block_size
        block_size=$(( 1 << (32 - cp) ))
        # Sibling starts immediately after current block
        local expected_sibling
        expected_sibling=$(( cni + block_size ))
        [ "$nni" -ne "$expected_sibling" ] && return 1
        # Both must be aligned to the merged (parent) prefix boundary
        local parent_size
        parent_size=$(( block_size * 2 ))
        local parent_mask
        parent_mask=$(( ~ (parent_size - 1) ))
        # Ensure cur_net_int is the lower sibling (aligned to parent boundary)
        if [ $(( cni & parent_mask )) -ne "$cni" ]; then
            return 1
        fi
        # Merge succeeds
        return 0
    }

    while IFS=' ' read -r net_i pref _orig; do
        if [ "$cur_net_int" -eq -1 ]; then
            # First entry
            cur_net_int="$net_i"
            cur_prefix="$pref"
            local span
            span=$(( 1 << (32 - cur_prefix) ))
            cur_end=$(( cur_net_int + span - 1 ))
            continue
        fi

        if [ "$net_i" -le "$cur_end" ]; then
            # Fully contained — skip
            true
        elif [ "$net_i" -eq $(( cur_end + 1 )) ] && _try_merge "$cur_net_int" "$cur_prefix" "$net_i" "$pref"; then
            # Adjacent aligned sibling — merge by reducing prefix by 1
            cur_prefix=$(( cur_prefix - 1 ))
            local merged_span
            merged_span=$(( 1 << (32 - cur_prefix) ))
            cur_end=$(( cur_net_int + merged_span - 1 ))
        else
            # Not contained and not a mergeable sibling — emit current, start new
            int_to_cidr "$cur_net_int" "$cur_prefix"
            cur_net_int="$net_i"
            cur_prefix="$pref"
            local new_span
            new_span=$(( 1 << (32 - cur_prefix) ))
            cur_end=$(( cur_net_int + new_span - 1 ))
        fi
    done <<< "$sorted_parsed"

    # Emit the last supernet
    if [ "$cur_net_int" -ne -1 ]; then
        int_to_cidr "$cur_net_int" "$cur_prefix"
    fi
}

# ---------------------------------------------------------------------------
# format_results — apply output format to a newline-separated list of CIDRs
# Reads lines from stdin, writes formatted output to stdout.
# ---------------------------------------------------------------------------
format_results() {
    local fmt="$1"
    local -a lines=()
    local line

    while IFS= read -r line || [ -n "$line" ]; do
        [ -n "$line" ] && lines+=("$line")
    done

    case "$fmt" in
        plain)
            local l
            for l in "${lines[@]+"${lines[@]}"}"; do
                printf '%s\n' "$l"
            done
            ;;
        json)
            printf '['
            local i=0
            local l
            for l in "${lines[@]+"${lines[@]}"}"; do
                if [ "$i" -eq 0 ]; then
                    printf '"%s"' "$l"
                else
                    printf ', "%s"' "$l"
                fi
                i=$(( i + 1 ))
            done
            printf ']\n'
            ;;
        csv)
            printf 'cidr\n'
            local l
            for l in "${lines[@]+"${lines[@]}"}"; do
                printf '%s\n' "$l"
            done
            ;;
        nmap)
            local first=true
            local l
            for l in "${lines[@]+"${lines[@]}"}"; do
                if "$first"; then
                    printf '%s' "$l"
                    first=false
                else
                    printf ' %s' "$l"
                fi
            done
            # Only print newline if there was any output
            if ! "$first"; then
                printf '\n'
            fi
            ;;
        *)
            log_error "Unknown format: '$fmt'. Valid: plain, json, csv, nmap"
            return 1
            ;;
    esac
}

# ---------------------------------------------------------------------------
# Parse flags
# ---------------------------------------------------------------------------
while getopts ':i:o:6rSs:d:F:Avqh' opt; do
    case "$opt" in
        i) INPUT_FILE="$OPTARG" ;;
        o) OUTPUT_FILE="$OPTARG" ;;
        6) IPV6=true ;;
        r) REVERSE=true ;;
        S) SORT=false ;;
        s)
            case "$OPTARG" in
                radb)  WHOIS_HOST="whois.radb.net" ;;
                ripe)  WHOIS_HOST="whois.ripe.net" ;;
                arin)  WHOIS_HOST="rr.arin.net" ;;
                apnic) WHOIS_HOST="whois.apnic.net" ;;
                *)     WHOIS_HOST="$OPTARG" ;;
            esac
            ;;
        d) DELAY="$OPTARG" ;;
        F)
            case "$OPTARG" in
                plain|json|csv|nmap) FORMAT="$OPTARG" ;;
                *)
                    log_error "Invalid format '$OPTARG'. Valid: plain, json, csv, nmap"
                    usage >&2
                    exit 1
                    ;;
            esac
            ;;
        A) AGGREGATE=true ;;
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
    printf '[ERROR] -v and -q are mutually exclusive\n' >&2
    exit 1
fi

# Validate DELAY is a valid non-negative number (integer or float)
case "$DELAY" in
    ''|*[!0-9.]*|*.*.*) 
        log_error "Invalid delay value: '$DELAY'. Must be a non-negative number."
        exit 1
        ;;
esac

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
first_target=true

for target in "${targets[@]}"; do
    # Apply delay between targets (not before the first one)
    if "$first_target"; then
        first_target=false
    else
        # Float-safe delay check via awk
        if awk "BEGIN{exit !($DELAY > 0)}"; then
            sleep "$DELAY"
        fi
    fi

    if "$REVERSE"; then
        result="$(reverse_lookup "$target")" || { lookup_error=2; continue; }
    else
        asn_num="$(normalise_asn "$target")" || { skipped_count=$((skipped_count + 1)); continue; }
        result="$(forward_lookup_with_fallback "$asn_num")" || { lookup_error=2; continue; }
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
# Sort/dedup
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

# ---------------------------------------------------------------------------
# Aggregate CIDRs if requested
# ---------------------------------------------------------------------------
if "$AGGREGATE"; then
    output="$(printf '%s\n' "$output" | aggregate_cidrs | sort -V)"
fi

# ---------------------------------------------------------------------------
# Format and emit
# ---------------------------------------------------------------------------
formatted_output="$(printf '%s\n' "$output" | format_results "$FORMAT")"

if [ -n "$OUTPUT_FILE" ]; then
    printf '%s\n' "$formatted_output" > "$OUTPUT_FILE"
    log_info "Results written to: $OUTPUT_FILE"
else
    [ -n "$formatted_output" ] && printf '%s\n' "$formatted_output"
fi

exit "$lookup_error"
