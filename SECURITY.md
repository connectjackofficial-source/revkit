# Security Policy

revkit is a read-only analysis tool: it parses files but never executes
their content, never unpacks and never touches the network.

## Supported versions

| Version | Supported          |
|---------|--------------------|
| 0.1.x   | :white_check_mark: |

## Reporting a vulnerability

If you find a bug that can crash the parser, hang it on crafted input, or
leak memory, please report it privately:

- Open a **private security advisory** via GitHub → *Security* →
  *Report a vulnerability*.
- Or email the maintainer through the address shown on the GitHub profile.

Please include:

- The affected module and function.
- A minimal reproducer (base64-encoded bytes are ideal).
- Expected vs actual behavior.

## What we promise

- Acknowledgement within 3 business days.
- A fix or a clear mitigation plan within 14 days for critical issues.
- Credit in the changelog unless you prefer to stay anonymous.

## Scope

- Parser robustness bugs (malformed headers, truncated buffers).
- Resource exhaustion on pathological files.
- Anything in the `revkit/` package.

Out of scope: vulnerabilities in third-party tools used to *produce* the
files you analyze.
