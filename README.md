# VecScan by Vectalith Labs

![Go](https://img.shields.io/badge/Go-1.20+-00ADD8?style=for-the-badge&logo=go&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Linux-lightgrey?style=for-the-badge)

**VecScan** is a high-performance, concurrent network scanning and reconnaissance tool built in Go. Designed with clean code principles, it focuses on robust architecture, strict rate limiting, and graceful resource management.

## Features

- **Concurrent TCP Scanning:** Fast, multi-threaded port scanning using Go's goroutines.
- **Strict Rate Limiting:** Prevents network saturation and reduces the likelihood of triggering simple rate-based defenses.
- **Graceful Shutdown:** Handles OS signals (`SIGINT`, `SIGTERM`) cleanly, ensuring no hanging goroutines or resource leaks.
- **Structured Reporting:** Outputs clean, machine-readable JSON alongside standard terminal text.
- **Web Application Scanning:** Basic Layer 7 reconnaissance, including security header analysis.
- **Vulnerability Mapping:** Conceptual integration for mapping detected service banners to known CVEs.

## Installation

Ensure you have Go installed on your system.

```bash
# Clone the repository
git clone https://github.com/yourusername/vecscan.git
cd vecscan

# Build the binary
go build -o vscan main.go

# (Optional) Move to a directory in your PATH
sudo mv vscan /usr/local/bin/