# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in AegisGate, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

### Contact

- **Developer:** Nik
- **GitHub:** [@NiklasNK-Creator](https://github.com/NiklasNK-Creator)

### Response Time

- Initial response: within 48 hours
- Fix timeline: depends on severity

### Scope

The following are in scope:
- Hypervisor escape vulnerabilities
- Stealth bypass (detection by anti-cheat)
- Crypto weaknesses (AES-GCM, key derivation)
- VMCALL authentication bypass
- NPT/EPT permission bypass
- USB monitor evasion

### Out of Scope

- Physical access attacks (DMA, cold boot)
- Social engineering
- Denial of service (guest can always crash itself)
