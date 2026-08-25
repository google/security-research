# kernelCTF Service (v5)

kernelCTF Service v5 is the remote evaluation and verification backend for Google's [kernelCTF](https://google.github.io/security-research/kernelctf/rules) vulnerability research and reward program. It provides an automated, secure environment to evaluate Linux kernel privilege escalation exploits, verify vulnerability triggers, and generate cryptographically signed verification flags.

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [How It Works](#how-it-works)
  - [1. Client Connection & Ingestion](#1-client-connection--ingestion)
  - [2. VM Execution & Isolation](#2-vm-execution--isolation)
  - [3. Evaluation Lifecycle & Actions](#3-evaluation-lifecycle--actions)
  - [4. Flag Generation & Signing](#4-flag-generation--signing)
- [Project Structure](#project-structure)
- [Kernel Releases & Automation](#kernel-releases--automation)
  - [Release Discovery (`tools/auto_release.py`)](#release-discovery-toolsauto_releasepy)
  - [Release Activation (`tools/activate_releases.py`)](#release-activation-toolsactivate_releasespy)
- [Server Setup & Deployment](#server-setup--deployment)
  - [Prerequisites](#prerequisites)
  - [Host Setup (`infra/setup.sh`)](#host-setup-infrasetupsh)
  - [Deploying to Remote VM (`infra/deploy.sh`)](#deploying-to-remote-vm-infradeploysh)
- [Testing & Client Evaluation](#testing--client-evaluation)
  - [Using `client/cli.py`](#using-clientclipy)
  - [Running the Test Suite (`tests/run_tests.sh`)](#running-the-test-suite-testsrun_testssh)
  - [Manual Interactive Shell (`client/connect.sh`)](#manual-interactive-shell-clientconnectsh)
- [Security & Anti-Spoofing Mitigations](#security--anti-spoofing-mitigations)

---

## Architecture Overview

```
                          +-----------------------------------+
                          |      Participant / Researcher     |
                          +-----------------------------------+
                                            |
                                 TLS 1.3 (Port 1337)
                                            v
                          +-----------------------------------+
                          |     socat + server/service.sh     |
                          +-----------------------------------+
                                            |
                                            v
                          +-----------------------------------+
                          |         server/server.py          |
                          |  - Ingests exploit via memfd      |
                          |  - Menu & Action Dispatcher       |
                          |  - HMAC Flag Generation           |
                          +-----------------------------------+
                                            |
                                            v
                          +-----------------------------------+
                          |          server/qemu.sh           |
                          |      server/vm/run_vmlinuz.sh     |
                          +-----------------------------------+
                                            |
                     +----------------------+----------------------+
                     | (KVM Virtualization)                        |
                     v                                             v
        +-------------------------+                   +---------------------------+
        | Hardened Kernel Target  |                   |   LTS / LTS-KASAN Target  |
        | (e.g. hardened-v1-7.2)  |                   |   (e.g. lts-6.12.x)       |
        | - Flag leak validation  |                   | - Vulnerability trigger   |
        | - 20 evaluation runs    |                   | - Kernel crash detection  |
        +-------------------------+                   +---------------------------+
```

---

## How It Works

### 1. Client Connection & Ingestion

1. The service listens on port `1337` via `socat` with TLS 1.3 encryption ([`server/service.sh`](server/service.sh)).
2. Once connected, [`server/server.py`](server/server.py) prompts the participant with the menu of active targets and actions (`lpe-test`, `vuln-test`, `evaluate`, `info`).
3. When an action is selected:
   - The client specifies the binary/script size (up to 50MB) and its SHA256 hash.
   - The binary data is streamed directly into an anonymous Linux memory file descriptor (`memfd_create`) via [`server/utils.py`](server/utils.py), avoiding writing untrusted exploit binaries to disk.

### 2. VM Execution & Isolation

1. [`server/qemu.sh`](server/qemu.sh) and [`server/vm/run_vmlinuz.sh`](server/vm/run_vmlinuz.sh) launch QEMU with KVM acceleration using the specified kernel release (`bzImage`).
2. Hardware virtualization features (such as **Intel IBT / CET**) are strictly validated upon boot inside [`server/vm/rootfs/init`](server/vm/rootfs/init).
3. The exploit file descriptor (`/proc/self/fd/<fd>`) and dynamic flag file are passed via QEMU drives/unmap devices and made accessible inside the VM:
   - `/flag` (mode `0400`, owned by `root`).
   - `/exploit` (executable).
4. Exploit commands run under an unprivileged user `user` (or `root` in root testing mode).
5. Output separation:
   - Command output is captured across dedicated serial channels (`/output` on `ttyS1`).
   - Kernel logs (`dmesg` on `ttyS0`) are captured independently for authentic panic and KASAN bug analysis.

### 3. Evaluation Lifecycle & Actions

| Action | Target(s) | Description |
| :--- | :--- | :--- |
| **`info`** | All active targets | Prints direct download links for target `bzImage`, `vmlinux.gz`, `.config`, `lakitu_defconfig`, and `COMMIT_INFO`. |
| **`lpe-test`** | Hardened Target (`hardened-v1-*`) | Single-run exploit test. Executes `/exploit` and checks if the participant can read and leak `/flag`. |
| **`vuln-test`** | LTS & LTS-KASAN Targets (`lts-*`, `lts-*-kasan`) | Runs `/exploit --vuln-trigger`. Verifies if the exploit triggers a genuine kernel panic or KASAN report in kernel `dmesg`. |
| **`evaluate`** | All Targets (LTS, LTS-KASAN, Hardened) | Full official evaluation workflow: <br>1. **Phase 1**: Runs `--vuln-trigger` up to 3 times on LTS-KASAN and LTS to confirm kernel crash.<br>2. **Phase 2**: Runs exploit 20 times on Hardened target to benchmark reliability and execution time.<br>3. **Phase 3**: If eligible and within the submission window, computes statistics and prints signed flag. |

### 4. Flag Generation & Signing

Verification flags are signed with HMAC-SHA1 using a secret key configured in `secrets/server_secrets.py`:

```
kernelCTF{v5:<hardened_target>+<lts_target>:<flag_id>:<attributes>:<timestamp>:<binary_hash>:<hmac_signature>}
```

* `attributes`: Tracks execution metrics across the 20 hardened runs (e.g. `time=1.23/1.18/-/0.95/...`).
* `binary_hash`: The SHA256 hash of the evaluated exploit binary.
* `timestamp`: UTC timestamp of the evaluation.

---

## Project Structure

```
.
├── config/                          # Configuration & release registries
│   ├── releases.yaml                # Target release registry & schedules
│   └── auto_release.yaml            # Channel filters & webhook settings
│
├── server/                          # Server backend & VM execution runtime
│   ├── service.sh                   # Socat TLS listener entrypoint (Port 1337)
│   ├── server.py                    # Main server interactive menu & dispatch
│   ├── utils.py                     # MemFd binary streaming, timing & process streamer
│   ├── qemu.sh                      # QEMU launcher & argument mapper
│   └── vm/                          # QEMU environment, initramfs builders & rootfs
│       ├── run_vmlinuz.sh
│       ├── update_rootfs_image.sh
│       └── rootfs/
│
├── tools/                           # Release pipeline & synchronization tasks
│   ├── auto_release.py              # GCS discovery daemon & notifier
│   ├── activate_releases.py         # Promotion from staging to active releases
│   ├── download_latest_releases.sh  # Manual release downloader helper
│   ├── pull_from_server.sh          # Sync logs/data from remote host
│   └── update_opensource.sh         # Upstream open-source sync tool
│
├── infra/                           # Deployment, VM setup, systemd & crontab
│   ├── deploy.sh                    # Remote VM staging & deployment orchestrator
│   ├── setup.sh                     # Idempotent host setup & dependency installer
│   ├── get_latest_lts.py            # LTS release parsing utility (used by setup.sh)
│   ├── server_cert_gen.sh           # TLS certificate generator
│   ├── systemd/
│   │   └── kernelctf.service        # Systemd service unit file
│   └── cron/
│       └── auto_release.cron        # Cron schedule definition
│
├── client/                          # Participant / researcher client tooling
│   ├── cli.py                       # Evaluation & test submission CLI client
│   ├── connect.sh                   # Interactive socat TLS remote shell client
│   ├── connect_local.sh             # Interactive socat TLS local shell client
│   └── server_cert.pem              # Public server certificate for TLS verification
│
├── tests/                           # Unit and integration test suite
│   ├── run_tests.sh                 # End-to-end multi-target test suite
│   ├── test_auto_release.py         # Unit tests for release automation
│   └── payloads/                    # Test exploit binaries & scripts
│       ├── test_exploit.sh
│       └── test_exploit_random.sh
│
├── secrets/                         # [Gitignored] Secrets, keys & certificates
│   ├── .gitignore                   # Ignores secrets while tracking examples
│   ├── server_secrets.py.example    # Example secrets template
│   ├── ssh_keys.txt.example         # Example SSH keys template
│   ├── server_secrets.py            # Active webhook URL, HMAC key, root hash
│   ├── kernelctf-vm-reader-sa-key.json # GCS service account key
│   ├── server_key.pem               # TLS private key
│   ├── server_cert_and_key.pem      # TLS certificate & private key
│   └── ssh_keys.txt                 # Authorized SSH keys for VM access
│
└── data/                            # [Gitignored] Runtime binary storage
    ├── releases/                    # Active downloaded production releases
    └── staging/                     # Staged upcoming releases
```

---

## Kernel Releases & Automation

Kernel builds are hosted on Google Cloud Storage (`gs://kernelctf-build/releases/`).

### Release Discovery (`tools/auto_release.py`)
Run periodically via cron ([`infra/cron/auto_release.cron`](infra/cron/auto_release.cron)):
1. Checks GCS bucket for newly published builds matching configured release channels in [`config/auto_release.yaml`](config/auto_release.yaml).
2. Downloads kernel images (`bzImage`, `vmlinux.gz`), configs, and commit info into `./data/staging/`.
3. Sends Discord notifications regarding upcoming release windows.

### Release Activation (`tools/activate_releases.py`)
Used to safely promote releases from `./data/staging/` to `./data/releases/`:
1. Validates required kernel configuration symbols (e.g. `CONFIG_IO_URING=y`, mitigation configs).
2. Verifies HTTP 200 accessibility for public artifacts on GCS.
3. Promotes verified builds to active `./data/releases/` directory.

---

## Server Setup & Deployment

### Prerequisites
- Linux host with `/dev/kvm` hardware virtualization support and Intel IBT/CET.
- Python 3.9+ with `pyyaml`, `httplib2`, `requests`.
- `socat`, `qemu-system-x86` (or QEMU 11 compiled by setup script), `iptables-persistent`.

### Host Setup (`infra/setup.sh`)

[`infra/setup.sh`](infra/setup.sh) is idempotent and configures the host environment:
```bash
sudo ./infra/setup.sh
```

It performs:
- Creation of system user `kernelctf` with `kvm` group access.
- Installation of authorized SSH keys from `secrets/ssh_keys.txt`.
- Installation of system dependencies and compilation of QEMU 11 (if missing).
- Generation of TLS certificate (`secrets/server_cert_and_key.pem`, `client/server_cert.pem`) via [`infra/server_cert_gen.sh`](infra/server_cert_gen.sh).
- GCS authentication and download of required active releases into `data/releases/`.
- Build of the initramfs image.
- Installation of auto-release cron jobs.
- Firewall configuration with rate-limiting on port `1337`.
- System limit tuning (`fs.aio-max-nr`, memlock) and starting `kernelctf.service`.

### Deploying to Remote VM (`infra/deploy.sh`)

To deploy local changes and secrets to a remote VM:
```bash
./infra/deploy.sh [TARGET_HOST]
# Example:
./infra/deploy.sh kernelctf.vrp.ctfcompetition.com
```

---

## Testing & Client Evaluation

### Using `client/cli.py`

[`client/cli.py`](client/cli.py) interacts with local or remote kernelCTF server instances. By default, it connects to the remote production service over TLS.

```bash
# Query active target release info and artifact URLs (no binary required)
python3 client/cli.py --action info

# Evaluate exploit against remote server (default target)
python3 client/cli.py exploit_binary --action evaluate

# Run lpe-test against remote server
python3 client/cli.py exploit_binary --action lpe-test

# Run vuln-test against custom remote target
python3 client/cli.py exploit_binary --action vuln-test --remote kernelctf.example.com:1337

# Test exploit against local server instance
python3 client/cli.py tests/payloads/test_exploit.sh --action lpe-test --local

# Local evaluation testing with overrides
python3 client/cli.py tests/payloads/test_exploit.sh \
  --action evaluate \
  --local \
  --ignore-open-slots \
  --show-vm-output \
  --root
```

### Running the Test Suite (`tests/run_tests.sh`)

Run the complete validation suite:
```bash
# Run against local server instance
./tests/run_tests.sh

# Run against remote TLS server
./tests/run_tests.sh --remote kernelctf.example.com:1337 -k
```

Tests include:
0. Unit test suite discovery (`tests/test_auto_release.py`).
1. `lpe-test` flag leak validation in root mode.
2. `vuln-test` kernel crash detection via SysRq panic in root mode.
3. `vuln-test` anti-spoofing verification (unprivileged userspace fake panic rejection).
4. `evaluate` full 20-run loop with simulated intermittent exploits and flag generation.

### Manual Interactive Shell (`client/connect.sh`)

To interactively connect to the service menu via TLS:
```bash
./client/connect.sh [TARGET_HOST:PORT]
```

---

## Security & Anti-Spoofing Mitigations

- **In-Memory Binary Ingestion**: Exploit payloads are stored in anonymous memory descriptors (`memfd`) and exposed read-only to QEMU without touching host persistent storage.
- **Kernel Panic Verification**: Vulnerability trigger crashes are verified using host-captured kernel ringbuffer (`dmesg`) output rather than userspace stdout, preventing fake panic string injection from unprivileged processes.
- **Rate Limiting**: Host firewall limits simultaneous connections per IP on port 1337.
- **Strict File Permissions**: Secrets and keys are restricted to `640` / `750` permissions inside `secrets/` accessible only by `kernelctf` service owner.
