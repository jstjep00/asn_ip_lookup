# asn_ip_lookup

Extract IP ranges allocated to Autonomous Systems (AS) using whois and regex. Supports forward lookup (ASN → IP ranges), reverse lookup (IP → ASN), IPv6 ranges, multi-server with auto-fallback, rate limiting, output format selection, CIDR aggregation, file I/O, and colorized verbose output.

## Requirements

- `bash` ≥ 4
- `whois`
- `awk` (for fractional delay comparison)

## Usage

```
asn_ip_lookup.sh [-i FILE] [-o FILE] [-6] [-r] [-S] [-s SERVER]
                 [-d SECS] [-F FORMAT] [-A] [-v|-q] [-h] [ASN...]
```

## Options

| Flag | Description |
|------|-------------|
| `-i FILE` | Read ASNs (or IPs in reverse mode) from `FILE`, one per line |
| `-o FILE` | Write results to `FILE` instead of stdout |
| `-6` | Also extract IPv6 ranges (forward lookup only) |
| `-r` | Reverse lookup: input is IPs/CIDRs, output is originating ASN(s) |
| `-S` | Disable sort and deduplication of output (default: sort+dedup on) |
| `-s SERVER` | Whois server preset or raw hostname. Presets: `radb`, `ripe`, `arin`, `apnic` |
| `-d SECS` | Delay between lookups in seconds (default: `0`); accepts fractional values |
| `-F FORMAT` | Output format: `plain` (default), `json`, `csv`, `nmap` |
| `-A` | Aggregate/merge overlapping IPv4 CIDRs (pure bash, no ipcalc) |
| `-v` | Verbose — colorized `[INFO]`/`[WARN]`/`[ERROR]` progress to stderr |
| `-q` | Quiet — suppress all stderr output |
| `-h` | Print help and exit 0 |

### Server presets (`-s`)

| Preset | Host |
|--------|------|
| `radb` | `whois.radb.net` (default) |
| `ripe` | `whois.ripe.net` |
| `arin` | `rr.arin.net` |
| `apnic` | `whois.apnic.net` |

A raw hostname is also accepted (e.g. `-s whois.example.net`).

**Auto-fallback**: if the primary server returns zero results for a forward lookup, the script automatically retries the fallback chain (`whois.radb.net → whois.ripe.net → rr.arin.net`) before reporting no results.

### Output formats (`-F`)

| Format | Description |
|--------|-------------|
| `plain` | One CIDR per line (default) |
| `json` | JSON array `["1.2.3.0/24", ...]` |
| `csv` | Single-column CSV with header `cidr` |
| `nmap` | Space-separated list (usable as `nmap` targets) |

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

### Use RIPE whois server

```bash
./asn_ip_lookup.sh -s ripe AS1234
```

### Use ARIN registry, JSON output

```bash
./asn_ip_lookup.sh -s arin -F json AS1234
```

### Rate-limited bulk lookup (1.5 s between queries)

```bash
./asn_ip_lookup.sh -d 1.5 -i asns.txt -o ranges.txt
```

### Aggregate overlapping CIDRs

```bash
./asn_ip_lookup.sh -A AS1234 AS5678
```

Merges overlapping or adjacent IPv4 CIDR blocks into minimal supernets using pure bash arithmetic.

### Aggregated output as nmap targets

```bash
./asn_ip_lookup.sh -A -F nmap AS1234 AS5678
```

### JSON output to file

```bash
./asn_ip_lookup.sh -F json -o ranges.json AS1234
```

### CSV output

```bash
./asn_ip_lookup.sh -F csv AS1234
# cidr
# 1.2.3.0/24
# ...
```

## Input File Format

```
# This is a comment — ignored
AS1234
AS5678
6447       # AS prefix is optional
```

## Notes

- ASN values are validated: non-numeric inputs are skipped with a warning; values of 0 or above 4 294 967 295 generate a warning but are still queried.
- Default whois host: `whois.radb.net`
- Forward lookup query: `whois -h <host> -i origin AS<N>`
- Reverse lookup query: `whois -h <host> -T route <IP>`
- Fractional sleep (`-d 0.5`) requires GNU `sleep` (standard on Linux).
- CIDR aggregation (`-A`) is IPv4 only; IPv6 ranges are passed through unmodified.
