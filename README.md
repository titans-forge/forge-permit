# Forge Permit

A small, synthetic feasibility demonstration for task-scoped agent permissions.
The trusted parent owns input and export directories, checks capabilities, and
records intent and completion receipts. A sandboxed scripted worker can read one
declared input, delegate narrower permissions, and export one bounded report.

## Run locally

Requires macOS with Seatbelt and Python 3.11 or newer. No package installation,
API keys, model download, internet service, or real business data is required.
From this directory:

```sh
python -m unittest discover -s tests -v
python -m forge_permit --output /tmp/forge-permit-demo-new
```

The output directory must not already exist. Exit 0 means the bounded live checks
passed; exit 1 means failure. The recorded observation used Python 3.13.12 on macOS 27.0.1 arm64.

Inspect `result.json`, `transcript.json`, `policy.json`, `sandbox.sb`,
`case/receipts.jsonl`, and `case/exports/report.txt`. Receipts contain action IDs,
policy hashes, decisions, outcomes and artifact hashes, without bearer tokens or
tool payload contents. Fixtures and the report are intentionally synthetic.

## What is tested

- Seven direct bypass probes: private-file read/write, direct input read,
  undeclared export creation, receipt read/write, and loopback network access.
- An unsandboxed positive control proves those same synthetic operations work.
- Permitted broker read and exact report export; undeclared read, traversal,
  oversized export and expanded child permissions denied.
- Narrow child permissions work and share ancestor quotas and revocation.
- Parent-side checks of output bytes, hashes, receipt lifecycle, unchanged
  canaries and absence of an unwanted network connection.
- Unit coverage includes concurrency, links, UTF-8 byte accounting, expired and
  unknown capabilities, audit failure, and preservation of existing evidence.

## Trust boundary and limits

This is a feasibility prototype, not a production security certification or a
general-purpose agent execution service. The host, Python runtime, bootstrap,
broker, policy author and fixture root ownership are trusted. Only the worker
after sandbox installation is restricted. The bootstrap preloads trusted modules
and installs a deny-by-default Seatbelt policy before reading worker input.
Installation failure aborts; there is no unrestricted fallback.

Direct `sandbox-exec` launches failed during this machine's dynamic-loader
startup. The working backend invokes the same OS sandbox mechanism using
`sandbox_init` after trusted interpreter startup. That deprecated macOS API is
a feasibility dependency, not a portable production backend.

System and Python runtime contents are readable, and general filesystem metadata
reads are allowed. This does not promise metadata secrecy. No network, subprocess
execution, or direct output write permission is granted. Worker descriptors are
limited to standard streams. A 15-second deadline, 32-frame request limit and
bounded pipe buffers constrain this fixed demonstration. CPU/memory resource
isolation and hostile native-code escape resistance are not qualified here.

Broker paths are single-component filenames; recursive cache trees, screenshots,
binary exports, shell commands, ROMA adapters and Linux containers are outside
this demonstration. Input/export roots must be privately owned and not mutated
by a hostile host. Read inputs are capped at 64 KiB. Aggregate export and call
quotas apply across descendants. Existing exports and receipts are not replaced.
Failed export attempts remain charged against quota.

Intent is persisted before effects; a missing terminal receipt means an unknown
outcome requiring operator review, never an automatic retry. An audit write or
fsync failure prevents further broker actions. Receipts are local evidence,
not cryptographically signed or tamper-proof against the trusted host. Capability
expiry uses wall-clock time; restart recovery and clock rollback resistance are
future work.

The scripted probes are reproducible tests, not proof against every malicious
agent. No LLM reliability, grant acceptance, full concept benchmark, Linux
isolation, or shared Forge deployment is claimed.

Read-access denials are measured by the fixed, source-hashed probe script's OS
exceptions. They are not independently traced by the parent or kernel telemetry.
The probe implementation is trusted test instrumentation; arbitrary agent claims
must never substitute for it. The parent separately checks filesystem effects,
exact artifacts, broker receipts, and accepted network connections. Positive
controls exercise the same probe code outside the sandbox.

## License and next gate

Apache-2.0, authorized by the owner for **Forge Permit only**. See LICENSE and
NOTICE. This repository contains the sanitized feasibility prototype. Publishing
it does not represent submission or approval of a funding application.

Start with [the demonstration walkthrough](DEMO_WALKTHROUGH.md).

Review the evidence before choosing a production backend. The next bounded gate
is an independently reviewed Linux adapter and adversarial test matrix, followed
by a single real agent integration if those checks pass. The larger proposal's
budget, benchmark and delivery commitments remain proposals.
