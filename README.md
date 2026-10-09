# ssldiag

`ssldiag` is a lightweight Python command-line tool for diagnosing SSL/TLS
connectivity and certificate problems.

It is intended for troubleshooting situations where a service is reachable
but an application reports an SSL/TLS, certificate, hostname/SNI, or
connectivity error.

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
- certificate validation error diagnosis
- TLS handshake error diagnosis

Additional diagnostic options include:

- force TLS 1.2 or TLS 1.3
- connect to a specific IP while keeping the expected TLS hostname
- override the TLS SNI/server hostname
- test an additional CA certificate or CA bundle
- provide a client certificate and private key for mTLS testing
- display the remote certificate in PEM format

If strict certificate validation fails, the tool makes a second connection
with certificate verification disabled **only to retrieve and inspect the
remote certificate**.

This fallback does not mean that the certificate is trusted.

If the TLS handshake itself fails, `ssldiag` does **not** retry in insecure
mode because certificate validation has not yet been reached.

## Requirements

- Python 3.10 or later
- `cryptography`

## Installation

Clone the repository and install it in editable mode:

```bash
git clone https://github.com/ThNeusius/ssldiag.git
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
usage: ssldiag [-h] [-p PORT] [-t TIMEOUT] [--show-pem]
               [--tls {auto,1.2,1.3}]
               [--connect-ip CONNECT_IP]
               [--sni SNI]
               [--ca-file CA_FILE]
               [--client-cert CLIENT_CERT]
               [--client-key CLIENT_KEY]
               [--version]
               [host]
```

`host` is optional when `--connect-ip` is used.

## Basic examples

Test a standard HTTPS server:

```bash
ssldiag example.com
```

Test a non-standard TLS port:

```bash
ssldiag example.com --port 8443
```

Increase the connection timeout:

```bash
ssldiag example.com --timeout 10
```

Display the peer certificate in PEM format:

```bash
ssldiag example.com --show-pem
```

## TLS version testing

Let Python/OpenSSL negotiate the TLS version automatically:

```bash
ssldiag example.com
```

Force TLS 1.2:

```bash
ssldiag example.com --tls 1.2
```

Force TLS 1.3:

```bash
ssldiag example.com --tls 1.3
```

This can help identify protocol-version compatibility problems between a
client and a server.

## Testing a specific IP address

You can connect directly to an IP address:

```bash
ssldiag --connect-ip 172.24.7.208 --port 443
```

In this case, no DNS hostname is available and TLS is attempted using the IP
address.

Many HTTPS servers, CDNs, reverse proxies, and load balancers require a valid
hostname through SNI. When the real hostname is known, prefer:

```bash
ssldiag server.example.com --connect-ip 172.24.7.208
```

This connects to:

```text
172.24.7.208
```

while using:

```text
server.example.com
```

for TLS SNI and certificate hostname validation.

This is useful for testing a specific backend, CDN node, reverse proxy, or
load-balancer address without changing DNS.

## Overriding SNI

The TLS server name can also be specified explicitly:

```bash
ssldiag --connect-ip 172.24.7.208 --sni server.example.com
```

This is mainly useful when testing an IP address directly.

## Testing an additional CA

If certificate validation fails because the issuer cannot be found locally,
you can test an additional CA certificate or CA bundle:

```bash
ssldiag server.example.com --ca-file my_ca.pem
```

This does not modify the operating-system certificate store. It only adds the
specified CA material for the current diagnostic test.

A common validation error is:

```text
unable to get local issuer certificate
```

This means that the certificate chain cannot be completed using the
certificates available to the client.

Possible causes include:

- a required intermediate CA is not sent by the server
- a required CA is missing from the local trust store
- the application uses a different CA store from the operating system

## mTLS / client certificate testing

For services that require mutual TLS (mTLS), provide a client certificate:

```bash
ssldiag server.example.com --client-cert client-cert.pem --client-key client-key.pem
```

If the certificate and private key are stored in the same PEM file:

```bash
ssldiag server.example.com --client-cert client.pem
```

This can help diagnose servers that reject the TLS handshake because a client
certificate is required or not accepted.

## Example output

```text
============================================================
 SSL/TLS DIAGNOSTIC TOOL v0.2.1
============================================================
[DNS] Resolving example.com...
  OK: 93.184.216.34

[TCP] Testing example.com:443...
  Trying ('93.184.216.34', 443)...
  OK: TCP connection established.

[TLS] Connection parameters
  Connect to  : example.com:443
  TLS hostname: example.com
  TLS version : auto

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

## Understanding common errors

### `unable to get local issuer certificate`

The TLS handshake reached certificate validation, but the client could not
build a complete trusted certificate chain.

Typical causes:

- missing intermediate CA on the server side
- missing CA in the local trust store
- application-specific trust store

### `TLSV1_ALERT_INTERNAL_ERROR`

The remote TLS endpoint aborted the handshake before certificate validation.

Possible causes include:

- missing or incorrect SNI
- server/CDN/load-balancer TLS configuration
- unsupported TLS parameters
- mTLS/client certificate requirement

### `SSLV3_ALERT_HANDSHAKE_FAILURE`

Despite the historical `SSLV3` name in the OpenSSL error text, this does not
necessarily mean that SSLv3 is being used.

The remote endpoint rejected the TLS handshake.

Possible causes include:

- incompatible TLS version or cipher policy
- client certificate/mTLS requirement
- incorrect SNI
- server-side TLS policy

### TLS handshake timeout

Example:

```text
The handshake operation timed out
```

This means that the TCP connection succeeded but the TLS handshake did not
receive a valid response before the timeout.

Possible causes include:

- the target port is not a TLS service
- the service uses plain HTTP
- the service expects another protocol before TLS
- a firewall or proxy is dropping TLS traffic
- the TLS service is not responding

For example, a successful TCP connection to an HTTP service on port `5000`
does not mean that the port supports TLS.

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

It is used only after strict certificate validation fails and should **not**
be interpreted as a successful security validation.

`ssldiag` does not send application data or credentials.

Client certificates and private keys passed with `--client-cert` and
`--client-key` are used only for the requested TLS diagnostic connection.

## Windows executable

A standalone Windows executable can be built with PyInstaller for systems
where Python is not installed.

Example:

```bash
pyinstaller --onefile --name ssldiag ssldiag.py
```

The executable is generated in:

```text
dist/ssldiag.exe
```

Usage examples:

```text
ssldiag.exe example.com
ssldiag.exe example.com --tls 1.2
ssldiag.exe server.example.com --connect-ip 172.24.7.208
ssldiag.exe --connect-ip 172.24.7.208 --port 443 --sni server.example.com
```

A standalone executable can also be distributed through GitHub Releases.

## Project scope

The goal of this project is deliberately limited: provide a small,
understandable diagnostic utility for common SSL/TLS connection issues.

Possible future additions include:

- full certificate-chain inspection
- HTTP/plain-text protocol detection
- proxy diagnostics
- JSON output for automated processing
- structured diagnostic reports

## License

Released under the MIT License.
