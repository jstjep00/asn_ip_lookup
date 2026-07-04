# asn_ip_lookup

Extract IP ranges allocated to Autonomous Systems (AS) using RADB whois and regex. Supports forward lookup (ASN → IP ranges), reverse lookup (IP → ASN), IPv6 ranges, file I/O, and colorized verbose output.

## Requirements

- `bash` ≥ 4
- `whois`

## Usage

```
asn_ip_lookup.sh [-i FILE] [-o FILE] [-6] [-r] [-S] [-v|-q] [-h] [ASN...]
```

## Options

| Flag | Description |
|------|-------------|
| `-i FILE` | Read ASNs (or IPs in reverse mode) from `FILE`, one per line |
| `-o FILE` | Write results to `FILE` instead of stdout |
| `-6` | Also extract IPv6 ranges (forward lookup only) |
| `-r` | Reverse lookup: input is IPs/CIDRs, output is originating ASN(s) |
| `-S` | Disable sort and deduplication of output (default: sort+dedup on) |
| `-v` | Verbose — colorized `[INFO]`/`[WARN]`/`[ERROR]` progress to stderr |
| `-q` | Quiet — suppress all stderr output |
| `-h` | Print help and exit 0 |

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Usage / argument error |
| `2` | Lookup error (whois failed) |

## Examples

### Basic forward lookup (single ASN)

```bash
./asn_ip_lookup.sh AS1234
```

### Multiple ASNs as positional args

```bash
./asn_ip_lookup.sh AS1234 AS5678
```

Results from all ASNs are merged, sorted, and deduplicated by default.

### File input / file output

```bash
./asn_ip_lookup.sh -i asns.txt -o ranges.txt
```

`asns.txt` should contain one ASN per line (with or without the `AS` prefix). Comments (`#`) and blank lines are ignored.

### IPv6 ranges

```bash
./asn_ip_lookup.sh -6 AS1234 AS5678
```

Outputs both IPv4 and IPv6 CIDR ranges.

### Reverse lookup (IP → ASN)

```bash
./asn_ip_lookup.sh -r 8.8.8.8
./asn_ip_lookup.sh -r 192.0.2.0/24
./asn_ip_lookup.sh -r -i ips.txt
```

Queries `whois.radb.net` for the originating ASN of each IP or CIDR prefix.

### Verbose progress

```bash
./asn_ip_lookup.sh -v -i asns.txt -o ranges.txt
```

Prints colorized `[INFO]` / `[WARN]` / `[ERROR]` messages to stderr while writing results to `ranges.txt`.

### Disable deduplication

```bash
./asn_ip_lookup.sh -S AS1234 AS5678
```

Outputs ranges in the order they are returned, without sorting or removing duplicates.

## Input File Format

```
# This is a comment — ignored
AS1234
AS5678
6447       # AS prefix is optional
```

## Notes

- ASN values are validated: non-numeric inputs are skipped with a warning; values of 0 or above 4 294 967 295 generate a warning but are still queried.
- Whois host: `whois.radb.net`
- Forward lookup query: `whois -h whois.radb.net -i origin AS<N>`
- Reverse lookup query: `whois -h whois.radb.net -T route <IP>`
