HTTP Request Smuggling Scanner v3
A comprehensive, safe, and high-performance HTTP request smuggling detection tool with advanced features for security professionals.

🚀 Features
Core Capabilities
Safe Scanning: GET-only requests with unique markers (non-destructive)

High Performance: Async implementation with configurable concurrency

Comprehensive Detection: 9+ smuggling techniques with advanced heuristics

Professional Reporting: JSON, CSV, and Markdown report generation

PoC Generation: Raw byte generation for manual reproduction

Advanced Features
Burp Collaborator Integration: Out-of-band detection for blind smuggling

HTTP/2 Support: Experimental HTTP/2 smuggling detection

Test Harness: Built-in vulnerable proxy+backend for lab testing

PCAP Capture: Optional traffic capture via tcpdump

CI/CD Ready: Exit codes and quiet mode for automation

TLS Hardening: Configurable certificate verification

🔍 Detection Techniques
The scanner tests for these HTTP request smuggling variants:

CL+TE Clash - Content-Length vs Transfer-Encoding conflict

TE+CL Mismatch - Transfer-Encoding with chunked body

CL+CL Conflict - Multiple Content-Length headers

Malformed Chunk Sizes - Incorrect chunk size declarations

Uppercase Chunk Hex - Case-sensitive chunk parsing

CRLF Injection - Header injection via CRLF sequences

Folded Headers - Obsolete header folding techniques

Expect: 100-continue - Expect header handling issues

OOB Detection - Burp Collaborator integration for blind attacks

📦 Installation
Prerequisites
bash
# Required
python3.7+

# Optional (for HTTP/2 support)
pip install httpx
Basic Setup
bash
git clone <repository-url>
cd http-smuggling-scanner
# No external dependencies required for basic functionality
🛠 Usage Examples
Basic Scanning
bash
# Single target
python3 http_smuggle_scanner3.py -u https://example.com

# Multiple targets from file
python3 http_smuggle_scanner3.py -L targets.txt --concurrency 50

# With professional reporting
python3 http_smuggle_scanner3.py -L targets.txt --markdown report.md --csv results.csv
Advanced Scanning
bash
# With OOB detection (Burp Collaborator)
python3 http_smuggle_scanner3.py -u https://target.com --collaborator xyz.oastify.com

# CI/CD pipeline integration
python3 http_smuggle_scanner3.py -L targets.txt --ci --quiet

# With traffic capture (requires root)
sudo python3 http_smuggle_scanner3.py -u https://target.com --pcap capture.pcap

# Custom TLS verification
python3 http_smuggle_scanner3.py -u https://target.com --ca-bundle custom-ca.pem
PoC Generation
bash
# Generate proof-of-concept payload
python3 http_smuggle_scanner3.py --poc "https://example.com/" CL+TE_clash --save-poc payload.raw

# Reproduce manually
openssl s_client -quiet -connect example.com:443 < payload.raw
Test Harness
bash
# Start local vulnerable environment
python3 http_smuggle_scanner3.py --harness --harness-frontend-port 8080 --harness-backend-port 9090

# Test against local harness
python3 http_smuggle_scanner3.py -u http://127.0.0.1:8080
📊 Output Formats
JSON Report
Detailed structured data with full scan results, timing information, and raw response snippets.

CSV Report
Condensed results for analysis in spreadsheet applications or data processing tools.

Markdown Report
Professional vulnerability report with clear status indicators and executive summary.

Console Output
Real-time progress updates and summary findings with severity indicators.

🔧 Technical Details
Architecture
Async Core: Built on asyncio for high-performance concurrent scanning

Template System: Modular payload generation for easy extensibility

Safety First: All tests use GET requests with unique markers to avoid destructive operations

Error Resilient: Comprehensive error handling and connection management

Detection Heuristics
Marker Reflection: Unique identifiers in responses indicate smuggling

Multiple HTTP Responses: Detection of pipelined responses

Length Analysis: Response size anomalies compared to baseline

Timing Analysis: Connection timing discrepancies

Security Considerations
Non-destructive testing approach

Configurable rate limiting via concurrency controls

Respects target systems with appropriate timeouts

Clear authorization requirements in documentation

🏗 Code Structure
text
http_smuggle_scanner3.py
├── Payload Builders (9+ techniques)
├── Async Networking Core
├── Analysis Heuristics
├── OOB Integration (Burp Collaborator)
├── HTTP/2 Support (Experimental)
├── Test Harness (Frontend/Backend)
├── Reporting Engine (JSON/CSV/Markdown)
└── CLI Interface
🎯 Use Cases
Security Teams
Regular vulnerability assessment of web applications

CI/CD pipeline integration for automated security testing

Pre-production environment validation

Penetration Testers
Comprehensive smuggling detection during engagements

Safe testing in production environments

Professional client reporting

Researchers
Protocol analysis and vulnerability research

Testing new smuggling techniques

Educational purposes and training

⚠️ Legal & Ethical Usage
IMPORTANT: This tool should only be used against:

Systems you own

Systems you have explicit written permission to test

Your own local test environments

Always ensure proper authorization before scanning any system.

🐛 Troubleshooting
Common Issues
bash
# Connection timeouts
python3 http_smuggle_scanner3.py -u https://target.com --timeout 15

# TLS certificate issues
python3 http_smuggle_scanner3.py -u https://target.com --ca-bundle custom-ca.pem

# Performance tuning
python3 http_smuggle_scanner3.py -L targets.txt --concurrency 20 --timeout 10
Debug Mode
For detailed output during scanning:

bash
python3 http_smuggle_scanner3.py -u https://target.com -v
🤝 Contributing
We welcome contributions! Areas for improvement:

Additional smuggling techniques

Enhanced HTTP/2 support

More output formats

Performance optimizations

Additional OOB detection methods
