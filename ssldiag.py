#!/usr/bin/env python3
"""
ssldiag - Lightweight SSL/TLS diagnostic tool.

Checks:
- DNS resolution
- TCP connectivity
- TLS handshake
- TLS version and cipher
- Certificate validation
- Certificate subject, issuer, validity dates and SAN entries

If strict certificate validation fails, ssldiag reconnects with certificate
verification disabled only to retrieve and inspect the remote certificate.
"""

from __future__ import annotations

import argparse
import socket
import ssl
from typing import Iterable

from cryptography import x509


DEFAULT_PORT = 443
DEFAULT_TIMEOUT = 5.0


def print_banner() -> None:
    print("=" * 60)
    print(" SSL/TLS DIAGNOSTIC TOOL")
    print("=" * 60)


def resolve_dns(host: str) -> list[str]:
    """Resolve a hostname and return unique IP addresses."""
    print(f"[DNS] Resolving {host}...")

    try:
        addr_info = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        print(f"  ERROR: DNS resolution failed: {exc}")
        return []

    addresses = []
    for family, _, _, _, sockaddr in addr_info:
        ip = sockaddr[0]
        if ip not in addresses:
            addresses.append(ip)

    if not addresses:
        print("  ERROR: no address returned.")
        return []

    for ip in addresses:
        print(f"  OK: {ip}")

    return addresses


def test_tcp(host: str, port: int, timeout: float) -> bool:
    """Try all resolved TCP endpoints until one succeeds."""
    print(f"\n[TCP] Testing {host}:{port}...")

    try:
        addr_info = socket.getaddrinfo(
            host,
            port,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        print(f"  ERROR: getaddrinfo failed: {exc}")
        return False

    for family, socktype, proto, _, sockaddr in addr_info:
        print(f"  Trying {sockaddr}...")

        sock = socket.socket(family, socktype, proto)
        sock.settimeout(timeout)

        try:
            sock.connect(sockaddr)
            print("  OK: TCP connection established.")
            return True
        except OSError as exc:
            print(f"  Failed: {exc}")
        finally:
            sock.close()

    print("  ERROR: unable to establish a TCP connection.")
    return False


def _format_name(name: x509.Name) -> str:
    return name.rfc4514_string() or "(empty)"


def _print_san_entries(cert: x509.Certificate) -> None:
    try:
        extension = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )
    except x509.ExtensionNotFound:
        print("  SAN        : absent")
        return

    values: Iterable[str] = extension.value.get_values_for_type(x509.DNSName)
    values = list(values)

    if values:
        print("  SAN        :")
        for value in values:
            print(f"    - {value}")
    else:
        print(f"  SAN        : {extension.value}")


def print_certificate(cert: x509.Certificate) -> None:
    """Display useful certificate information."""
    print("\n[Certificate]")
    print(f"  Subject    : {_format_name(cert.subject)}")
    print(f"  Issuer     : {_format_name(cert.issuer)}")

    # cryptography >= 42 provides timezone-aware UTC properties.
    not_before = getattr(
        cert, "not_valid_before_utc", cert.not_valid_before
    )
    not_after = getattr(
        cert, "not_valid_after_utc", cert.not_valid_after
    )

    print(f"  Valid from : {not_before}")
    print(f"  Valid to   : {not_after}")
    print(f"  Serial     : {cert.serial_number}")
    _print_san_entries(cert)


def certificate_from_der(der_certificate: bytes) -> x509.Certificate:
    return x509.load_der_x509_certificate(der_certificate)


def perform_tls_handshake(
    host: str,
    port: int,
    timeout: float,
    *,
    verify: bool,
) -> tuple[str | None, tuple | None, bytes]:
    """Connect with TLS and return protocol, cipher and peer certificate."""
    if verify:
        context = ssl.create_default_context()
    else:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls_socket:
            der_cert = tls_socket.getpeercert(binary_form=True)
            if not der_cert:
                raise ssl.SSLError("The peer did not provide a certificate.")

            return tls_socket.version(), tls_socket.cipher(), der_cert


def print_tls_details(version: str | None, cipher: tuple | None) -> None:
    print(f"  TLS version : {version or 'unknown'}")

    if cipher:
        cipher_name, protocol, bits = cipher
        print(f"  Cipher      : {cipher_name}")
        print(f"  Cipher bits : {bits}")
        if protocol:
            print(f"  Cipher proto: {protocol}")
    else:
        print("  Cipher      : unknown")


def diagnose_tls(host: str, port: int, timeout: float, show_pem: bool) -> bool:
    """Run strict TLS validation and diagnostic fallback if needed."""
    print("\n[TLS] Strict certificate validation...")

    try:
        version, cipher, der_cert = perform_tls_handshake(
            host,
            port,
            timeout,
            verify=True,
        )
    except ssl.SSLCertVerificationError as exc:
        print("  ERROR: certificate validation failed.")
        print(f"  Verify code : {exc.verify_code}")
        print(f"  Message     : {exc.verify_message}")
        print(
            "\n[TLS] Reconnecting without certificate verification "
            "for diagnostic inspection only..."
        )
    except ssl.SSLError as exc:
        print(f"  ERROR: TLS handshake failed: {exc}")
        return False
    except OSError as exc:
        print(f"  ERROR: connection failed: {exc}")
        return False
    else:
        print("  OK: certificate validation succeeded.")
        print_tls_details(version, cipher)

        cert = certificate_from_der(der_cert)
        print_certificate(cert)

        if show_pem:
            print("\n[Certificate PEM]\n")
            print(ssl.DER_cert_to_PEM_cert(der_cert))

        return True

    # Diagnostic fallback: retrieve the certificate without trusting it.
    try:
        version, cipher, der_cert = perform_tls_handshake(
            host,
            port,
            timeout,
            verify=False,
        )
    except (ssl.SSLError, OSError) as exc:
        print(f"  ERROR: diagnostic TLS connection also failed: {exc}")
        return False

    print("  OK: diagnostic TLS connection established.")
    print("  WARNING: certificate verification is disabled for this connection.")
    print_tls_details(version, cipher)

    cert = certificate_from_der(der_cert)
    print_certificate(cert)

    if show_pem:
        print("\n[Certificate PEM]\n")
        print(ssl.DER_cert_to_PEM_cert(der_cert))

    return False


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Diagnose DNS, TCP and SSL/TLS connectivity.",
        epilog="ssldiag - 2026",
    )
    parser.add_argument(
        "host",
        help="Hostname or IP address, for example example.com",
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help=f"TCP port (default: {DEFAULT_PORT})",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"Connection timeout in seconds (default: {DEFAULT_TIMEOUT:g})",
    )
    parser.add_argument(
        "--show-pem",
        action="store_true",
        help="Print the peer certificate in PEM format.",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")

    if args.timeout <= 0:
        parser.error("timeout must be greater than zero")

    print_banner()

    if not resolve_dns(args.host):
        return 1

    if not test_tcp(args.host, args.port, args.timeout):
        return 2

    strict_validation_ok = diagnose_tls(
        args.host,
        args.port,
        args.timeout,
        args.show_pem,
    )

    return 0 if strict_validation_ok else 3


if __name__ == "__main__":
    raise SystemExit(main())
