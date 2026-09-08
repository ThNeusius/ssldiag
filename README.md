# ssldiag

`ssldiag` is a lightweight Python command-line tool for diagnosing SSL/TLS
connectivity and certificate problems.

It is intended for troubleshooting situations where a service is reachable
but an application reports an SSL/TLS or certificate error.

## Features

`ssldiag` performs the following checks:

- DNS resolution
- TCP connectivity
- TLS handshake
- negotiated TLS version
- negotiated cipher
- certificate trust validation
- certificate subject and issuer
- certificate validity period
- Subject Alternative Name (SAN) inspection

If strict certificate validation fails, the tool makes a second connection
with certificate verification disabled **only to retrieve and inspect the
remote certificate**.

This fallback does not mean that the certificate is trusted.

## Requirements

- Python 3.10 or later
- `cryptography`

## Installation

Clone the repository and install it in editable mode:

```bash
git clone https://github.com/<your-account>/ssldiag.git
cd ssldiag
python -m pip install -e .
```

You can then run:

```bash
ssldiag example.com
```

The script can also be executed directly:

```bash
python ssldiag.py example.com
```

## Usage

```text
usage: ssldiag [-h] [-p PORT] [-t TIMEOUT] [--show-pem] host
```

Examples:

```bash
ssldiag example.com
ssldiag example.com --port 8443
ssldiag example.com --timeout 10
ssldiag example.com --show-pem
```

## Example output

```text
============================================================
 SSL/TLS DIAGNOSTIC TOOL
============================================================
[DNS] Resolving example.com...
  OK: 93.184.216.34

[TCP] Testing example.com:443...
  Trying ('93.184.216.34', 443)...
  OK: TCP connection established.

[TLS] Strict certificate validation...
  OK: certificate validation succeeded.
  TLS version : TLSv1.3
  Cipher      : TLS_AES_256_GCM_SHA384

[Certificate]
  Subject    : CN=example.com
  Issuer     : CN=Example CA
  Valid from : ...
  Valid to   : ...
  SAN        :
    - example.com
```

The exact output depends on the target server and network environment.

## Exit codes

| Code | Meaning |
|---:|---|
| `0` | DNS, TCP and strict TLS certificate validation succeeded |
| `1` | DNS resolution failed |
| `2` | TCP connection failed |
| `3` | strict certificate validation failed, or TLS diagnosis was incomplete |

An exit code of `3` can still mean that the diagnostic fallback successfully
retrieved the certificate. The textual output should then be inspected.

## Security note

The diagnostic fallback deliberately disables certificate verification in
order to inspect a certificate that failed normal validation.

It is used only after strict validation fails and should **not** be interpreted
as a successful security validation.

`ssldiag` does not send application data or credentials.

## Project scope

The goal of this project is deliberately limited: provide a small,
understandable diagnostic utility for common SSL/TLS connection issues.

Possible future additions include:

- certificate chain inspection
- explicit hostname mismatch reporting
- protocol-version testing
- proxy diagnostics
- JSON output for automated processing

## Windows executable

A standalone Windows executable is available for users who do not have
Python installed.

Usage:

```text
ssldiag.exe example.com

## License

Released under the MIT License.
