This Python script is a **safe, non-destructive, asynchronous HTTP request smuggling scanner** with additional features like **PoC generation**, **local test harness**, **Burp Collaborator OOB detection**, **HTTP/2 probing**, **reporting**, and **CI/CD support**.

Below is a **detailed breakdown** of its structure, components, and functionality.

---

## 🔍 **Purpose & Safety Philosophy**

- **Goal**: Detect HTTP request smuggling vulnerabilities **without causing side effects** (e.g., no POSTs, no state changes).
- **Safety**: All "smuggled" requests are **GETs to unique, harmless paths** like `/{random_marker}/poc_*`, minimizing risk.
- **Ethical Use**: Designed for **authorized testing only**.

---

## 🧱 **Core Components**

### 1. **Payload Builders (Smuggling Techniques)**
Each function constructs a raw HTTP/1.1 request (as bytes) that attempts to exploit parser inconsistencies between frontend (e.g., CDN, load balancer) and backend servers.

| Technique | Description |
|--------|-------------|
| `build_baseline_get` | Normal GET request — used as control for comparison |
| `build_cl_te_clash` | **CL.TE**: `Content-Length` + `Transfer-Encoding: chunked` conflict |
| `build_te_cl_mismatch` | **TE.CL**: `Transfer-Encoding` + `Content-Length` (chunked body smuggles extra request) |
| `build_cl_cl_conflict` | Two `Content-Length` headers with different values |
| `build_malformed_chunk_size` | Declares chunk size ≠ actual size |
| `build_uppercase_chunk_hex` | Uses uppercase hex in chunk size (some parsers reject this) |
| `build_crlf_injection_variant` | Injects `\r\n\r\n` mid-headers to terminate early |
| `build_folded_header_variant` | Uses line folding (leading whitespace) — deprecated but sometimes parsed |
| `build_expect_100_safe` | Leverages `Expect: 100-continue` behavior |

> ✅ All smuggled payloads are **GET requests** to marker paths — **non-destructive**.

---

### 2. **OOB (Out-of-Band) Detection via Burp Collaborator**
- If `--collaborator xyz.oastify.com` is provided:
  - Generates a unique subdomain: `{uid}.xyz.oastify.com`
  - Smuggles a request to that host
  - If the backend resolves or connects to it → **confirms vulnerability**
- Adds a special payload: `CL+TE_OOB`

> 🔎 **Manual verification required**: You must check Burp Collaborator for DNS/HTTP interactions.

---

### 3. **Async Networking Engine**
- Uses `asyncio.open_connection()` for raw TCP (with SSL support)
- Supports:
  - TLS/SSL (with optional CA bundle for verification)
  - Custom timeouts
  - Connection reuse simulation via `Connection: keep-alive`
- Returns raw response bytes + timing + errors

> ⚡ High concurrency via `asyncio.Semaphore` (default: 50 concurrent targets)

---

### 4. **Heuristic Analysis**
Compares baseline vs. test responses using:
- Presence of **random marker** in response → indicates smuggled request was processed
- **Multiple HTTP responses** in one reply → classic sign of smuggling
- **Response length deviation** (>25%) → potential anomaly

> ❗ Not definitive — **manual verification recommended**

---

### 5. **HTTP/2 Smuggling (Experimental)**
- Uses `httpx` (if installed) to probe HTTP/2 support
- Currently **does not perform actual H2 smuggling** — just detects if H2 is used
- Future versions could add H2-specific techniques (e.g., stream multiplexing abuse)

---

### 6. **Local Test Harness (Lab Validation)**
Two async servers:
- **Backend** (`:9090`): Logs all received raw requests
- **Frontend Proxy** (`:8080`): Naively forwards bytes to backend (no parsing)

> 💡 Simulates a vulnerable proxy/backend setup for safe testing

Run with:
```bash
python3 http_smuggle_scanner_safe_async.py --harness
```

Then test against `http://127.0.0.1:8080`

---

### 7. **PoC (Proof-of-Concept) Generator**
- `--poc "https://target.com" CL+TE_clash`
- Outputs:
  - Raw bytes (hex preview)
  - Netcat / OpenSSL reproduction commands
  - Optional file save (`--save-poc poc.raw`)

Example output:
```bash
# Plain TCP reproduce:
# echo -ne '<raw>' | nc target.com 443
# TLS reproduce:
# openssl s_client -quiet -connect target.com:443 < poc.raw
```

---

### 8. **Reporting & Output**
Saves results in multiple formats:
- **JSON** (`-o results.json`) → full details
- **CSV** (`--csv results.csv`) → for spreadsheets
- **Markdown** (`--markdown report.md`) → human-readable table

Sample Markdown report:
| Target | Vulnerable? | Findings |
|--------|-------------|----------|
| https://target.com | 🔴 **Yes** | CL+TE_clash |
| https://example.com | 🟢 No | No anomalies |

---

### 9. **CI/CD Integration**
- `--ci` flag → exits with code `1` if **any suspect found**
- Useful in automated pipelines:
  ```bash
  python3 scanner.py -u https://prod-api.com --ci --quiet
  # Fails build if smuggling suspected
  ```

---

### 10. **PCAP Capture (Optional)**
- `--pcap capture.pcap` → runs `tcpdump` in background
- Captures raw traffic for forensic analysis
- Requires `tcpdump` and root privileges

---

## 🛠️ **Usage Examples**

### Scan a single target
```bash
python3 http_smuggle_scanner_safe_async.py -u https://target.com
```

### Scan list with OOB detection
```bash
python3 scanner.py -L targets.txt --collaborator xyz.oastify.com --concurrency 100
```

### Generate PoC
```bash
python3 scanner.py --poc "https://target.com" CL+TE_clash --save-poc exploit.raw
```

### Run local test lab
```bash
python3 scanner.py --harness --harness-frontend-port 8080
```

### CI mode (fail on findings)
```bash
python3 scanner.py -u https://api.example.com --ci --quiet
```

---

## 🔒 **Security & Limitations**

### ✅ Safe by design:
- No destructive methods (only GET)
- Unique markers avoid polluting logs
- No credential leakage

### ⚠️ Limitations:
- **Heuristics can have false positives/negatives**
- **HTTP/2 support is minimal**
- **Does not bypass WAFs or advanced protections**
- **OOB requires manual verification**

---

## 📦 **Dependencies**
- Python 3.7+
- `httpx` (optional, for HTTP/2)
- `tcpdump` (optional, for PCAP)

Install optional deps:
```bash
pip install httpx
```

---

## 🧪 **Why This Matters**
HTTP request smuggling can lead to:
- Cache poisoning
- Session hijacking
- Bypassing security controls
- SSRF and internal system access

