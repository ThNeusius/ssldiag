"""
ssldiag - Lightweight SSL/TLS diagnostic tool.

Checks:
- DNS resolution
- TCP connectivity
- TLS handshake
- TLS version and cipher
- Certificate validation
- Certificate subject, issuer, validity dates and SAN entries

Diagnostic options:
- force TLS 1.2 or TLS 1.3
- connect to a specific IP while keeping the correct TLS hostname/SNI
- use an explicit SNI name
- add a CA file for validation testing
- provide a client certificate/key for mTLS testing
"""
from __future__ import annotations

import argparse
import ipaddress
import socket
import ssl
from typing import Iterable

from cryptography import x509

VERSION = "0.2.1"
DEFAULT_PORT = 443
DEFAULT_TIMEOUT = 5.0


def print_banner() -> None:
    print("=" * 60)
    print(f" SSL/TLS DIAGNOSTIC TOOL v{VERSION}")
    print("=" * 60)


def is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def resolve_dns(host: str) -> list[str]:
    print(f"[DNS] Resolving {host}...")
    if is_ip_address(host):
        print(f"  INFO: target is already an IP address: {host}")
        return [host]
    try:
        addr_info = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        print(f"  ERROR: DNS resolution failed: {exc}")
        return []

    addresses: list[str] = []
    for _, _, _, _, sockaddr in addr_info:
        ip = sockaddr[0]
        if ip not in addresses:
            addresses.append(ip)
    for ip in addresses:
        print(f"  OK: {ip}")
    return addresses


def test_tcp(target: str, port: int, timeout: float) -> bool:
    print(f"\n[TCP] Testing {target}:{port}...")
    try:
        addr_info = socket.getaddrinfo(target, port, type=socket.SOCK_STREAM)
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
        extension = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
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
    print("\n[Certificate]")
    print(f"  Subject    : {_format_name(cert.subject)}")
    print(f"  Issuer     : {_format_name(cert.issuer)}")
    not_before = getattr(cert, "not_valid_before_utc", cert.not_valid_before)
    not_after = getattr(cert, "not_valid_after_utc", cert.not_valid_after)
    print(f"  Valid from : {not_before}")
    print(f"  Valid to   : {not_after}")
    print(f"  Serial     : {cert.serial_number}")
    _print_san_entries(cert)


def certificate_from_der(der_certificate: bytes) -> x509.Certificate:
    return x509.load_der_x509_certificate(der_certificate)


def configure_tls_version(context: ssl.SSLContext, tls_version: str) -> None:
    if tls_version == "1.2":
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.maximum_version = ssl.TLSVersion.TLSv1_2
    elif tls_version == "1.3":
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3


def build_ssl_context(*, verify: bool, tls_version: str, ca_file: str | None,
                      client_cert: str | None, client_key: str | None) -> ssl.SSLContext:
    if verify:
        context = ssl.create_default_context()
        if ca_file:
            context.load_verify_locations(cafile=ca_file)
    else:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    configure_tls_version(context, tls_version)
    if client_cert:
        context.load_cert_chain(certfile=client_cert, keyfile=client_key)
    return context


def perform_tls_handshake(connect_host: str, port: int, timeout: float,
                          server_name: str, *, verify: bool, tls_version: str,
                          ca_file: str | None, client_cert: str | None,
                          client_key: str | None) -> tuple[str | None, tuple | None, bytes]:
    context = build_ssl_context(
        verify=verify,
        tls_version=tls_version,
        ca_file=ca_file,
        client_cert=client_cert,
        client_key=client_key,
    )
    with socket.create_connection((connect_host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=server_name) as tls_socket:
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


def explain_verification_error(exc: ssl.SSLCertVerificationError) -> None:
    message = (exc.verify_message or "").lower()
    print("\n[Certificate validation diagnosis]")
    if "unable to get local issuer certificate" in message:
        print("  Meaning     : the issuer chain could not be completed locally.")
        print("  Likely causes:")
        print("    - a required intermediate CA is not sent by the server")
        print("    - a required CA is missing from the local trust store")
        print("    - the application uses a different CA store from the OS")
        print("  Next checks : inspect Issuer, server chain and local CA store")
    elif "certificate has expired" in message:
        print("  Meaning     : the certificate is expired.")
    elif "certificate is not yet valid" in message:
        print("  Meaning     : the certificate validity period has not started.")
    elif "hostname mismatch" in message or "ip address mismatch" in message:
        print("  Meaning     : the certificate does not match the requested hostname.")
        print("  Next check  : verify hostname/SNI and certificate SAN entries.")
    elif "self-signed certificate" in message:
        print("  Meaning     : a self-signed certificate is not trusted locally.")
    elif "unable to verify the first certificate" in message:
        print("  Meaning     : the server certificate chain cannot be completed.")
        print("  Likely cause: missing intermediate certificate.")
    else:
        print("  Meaning     : certificate validation failed.")


def explain_handshake_error(exc: ssl.SSLError) -> None:
    text = str(exc).lower()
    print("\n[TLS handshake diagnosis]")
    print("  Certificate validation was not reached.")
    if "handshake failure" in text:
        print("  Remote alert: handshake_failure")
        print("  Possible causes:")
        print("    - incompatible TLS version or cipher policy")
        print("    - client certificate/mTLS requirement")
        print("    - incorrect SNI/virtual host")
        print("    - server-side TLS policy")
    elif "internal error" in text:
        print("  Remote alert: internal_error")
        print("  Possible causes:")
        print("    - incorrect or missing SNI")
        print("    - server/CDN/load-balancer TLS configuration")
        print("    - unsupported TLS parameters")
        print("    - client certificate/mTLS requirement")
    else:
        print(f"  TLS error   : {exc}")


def diagnose_tls(hostname: str, connect_host: str, server_name: str, port: int,
                 timeout: float, show_pem: bool, tls_version: str,
                 ca_file: str | None, client_cert: str | None,
                 client_key: str | None) -> bool:
    print("\n[TLS] Connection parameters")
    print(f"  Connect to  : {connect_host}:{port}")
    print(f"  TLS hostname: {server_name}")
    print(f"  TLS version : {tls_version if tls_version != 'auto' else 'auto'}")

    print("\n[TLS] Strict certificate validation...")
    try:
        version, cipher, der_cert = perform_tls_handshake(
            connect_host, port, timeout, server_name,
            verify=True, tls_version=tls_version, ca_file=ca_file,
            client_cert=client_cert, client_key=client_key,
        )
    except ssl.SSLCertVerificationError as exc:
        print("  ERROR: certificate validation failed.")
        print(f"  Verify code : {exc.verify_code}")
        print(f"  Message     : {exc.verify_message}")
        explain_verification_error(exc)
        print("\n[TLS] Reconnecting without certificate verification for diagnostic inspection only...")
    except ssl.SSLError as exc:
        print(f"  ERROR: TLS handshake failed: {exc}")
        explain_handshake_error(exc)
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

    try:
        version, cipher, der_cert = perform_tls_handshake(
            connect_host, port, timeout, server_name,
            verify=False, tls_version=tls_version, ca_file=None,
            client_cert=client_cert, client_key=client_key,
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
        epilog="ssldiag - diagnostic utility",
    )
    parser.add_argument("host", nargs="?", help="Expected TLS hostname, for example example.com. Optional when --connect-ip is used.")
    parser.add_argument("-p", "--port", type=int, default=DEFAULT_PORT,
                        help=f"TCP port (default: {DEFAULT_PORT})")
    parser.add_argument("-t", "--timeout", type=float, default=DEFAULT_TIMEOUT,
                        help=f"Connection timeout in seconds (default: {DEFAULT_TIMEOUT:g})")
    parser.add_argument("--show-pem", action="store_true",
                        help="Print the peer certificate in PEM format.")
    parser.add_argument("--tls", choices=("auto", "1.2", "1.3"), default="auto",
                        help="TLS version to test (default: auto).")
    parser.add_argument("--connect-ip",
                        help="Connect to this IP while validating against HOST (useful for CDN/load-balancer tests).")
    parser.add_argument("--sni",
                        help="Override the TLS SNI/server hostname. Normally HOST is used.")
    parser.add_argument("--ca-file",
                        help="Additional CA certificate/bundle (PEM) for validation testing.")
    parser.add_argument("--client-cert", help="Client certificate PEM for mTLS testing.")
    parser.add_argument("--client-key", help="Client private key PEM for mTLS testing.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")
    if args.timeout <= 0:
        parser.error("timeout must be greater than zero")
    if args.client_key and not args.client_cert:
        parser.error("--client-key requires --client-cert")

    if not args.host and not args.connect_ip:
        parser.error("host is required unless --connect-ip is provided")

    print_banner()

    hostname = args.host or args.connect_ip
    connect_host = args.connect_ip or hostname
    server_name = args.sni or hostname

    if is_ip_address(hostname) and not args.sni:
        print("[INFO] No DNS hostname/SNI was provided; TLS will be attempted using the IP address.")
        print("       If the server requires SNI, use --sni <hostname>.")

    if args.host and args.connect_ip:
        addresses = resolve_dns(args.host)
        if addresses and args.connect_ip not in addresses:
            print(f"  WARNING: {args.connect_ip} is not among the currently resolved addresses for {args.host}.")
    elif args.host:
        if not resolve_dns(args.host):
            return 1
    else:
        print(f"[DNS] Skipped: direct IP target {args.connect_ip}")

    if not test_tcp(connect_host, args.port, args.timeout):
        return 2

    ok = diagnose_tls(
        hostname=hostname,
        connect_host=connect_host,
        server_name=server_name,
        port=args.port,
        timeout=args.timeout,
        show_pem=args.show_pem,
        tls_version=args.tls,
        ca_file=args.ca_file,
        client_cert=args.client_cert,
        client_key=args.client_key,
    )
    return 0 if ok else 3


if __name__ == "__main__":
    raise SystemExit(main())

