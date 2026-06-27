# whodat

A command-line reconnaissance tool that performs DNS lookups, geolocation, HTTP header inspection, port scanning, SSL certificate analysis, and VirusTotal scanning on a given domain or IP address.

## Requirements

```
pip install -r requirements.txt
```

## Configuration

Create a `.env` file in the same directory with your API keys:

```
IPINFO_TOKEN=your_ipinfo_token
VT_KEY=your_virustotal_api_key
```

Both keys are optional — the corresponding lookup will be skipped if a key is missing.

## Usage

```
python whodat.py <domain> [--json]
```

**Examples:**

```bash
python whodat.py google.com
python whodat.py 8.8.8.8
python whodat.py fccn.pt --json
```

## Options

| Flag | Description |
|------|-------------|
| `domain` | Domain name or IP address to look up |
| `--json` | Export the full report to a JSON file |

When `--json` is used, the report is saved as `<target>_Analysis_<timestamp>` in the current directory.

## Output

The tool prints a formatted report to the terminal with the following sections:

- **DNS Info** — hostname, aliases, and resolved IP addresses
- **Geolocation** — country, city, region, coordinates, and ASN (requires `IPINFO_TOKEN`)
- **HTTP Headers** — response headers from the target, tried over HTTPS then HTTP
- **VirusTotal** — malicious, suspicious, harmless, and undetected engine counts (requires `VT_KEY`)
- **Open Ports** — status of common ports: 21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 5432, 8080, 8443
- **SSL Info** — subject, issuer, validity dates, and Subject Alternative Names; expiry shown in red if expired
