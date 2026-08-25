# kernelCTF Auto-Release Automation (`tools/auto_release.py`)

## Overview

The `tools/auto_release.py` script automates the end-to-end lifecycle of discovering, staging, testing, activating, and announcing new Linux kernel releases for the kernelCTF service.

It runs on a **14-day (bi-weekly) recurring cycle** via a daily cron job scheduled at **12:00 UTC**.

---

## The Release Timeline & Lifecycle

```
Week 1 (Preparation & Announcement):
┌──────────────────────────────────────┐       ┌──────────────────────────────────────┐
│           Monday 12:00 UTC           │       │          Wednesday 12:00 UTC         │
│  - Query GCS for new LTS builds      │  ──>  │  - Promote staging -> releases/      │
│  - Download to data/staging/         │       │  - Post Discord announcement with:   │
│  - Update config/releases.yaml       │       │    • Target names                    │
│  - Run dry-run activation check      │       │    • Slot opening (Next Mon 12:00)   │
│  - Send Google Chat maintainer alert │       │    • Slot closing (Next Fri 12:00)   │
└──────────────────────────────────────┘       └──────────────────────────────────────┘
                                                                  │
Week 2 (Evaluation Submission Window):                            ▼
┌──────────────────────────────────────┐       ┌──────────────────────────────────────┐
│           Monday 12:00 UTC           │       │           Friday 12:00 UTC           │
│  - Evaluation window OPENS           │  ──>  │  - Evaluation window CLOSES          │
│  - server.py accepts exploits and    │       │  - Unflagged evaluations or testing  │
│    generates signed HMAC flags       │       │    only after this point             │
└──────────────────────────────────────┘       └──────────────────────────────────────┘
```

---

## Detailed Step-by-Step Flow

### 1. Week 1: Monday 12:00 UTC — Discovery & Preparation
- **Cron Invocation**: Triggered by `infra/cron/auto_release.cron` at `12:00 UTC`.
- **GCS Discovery**: Authenticates using `secrets/kernelctf-vm-reader-sa-key.json` and lists `gs://kernelctf-build/releases/` to find builds matching active targets (`TARGETS = ["lts-6.12"]`).
- **Filter Unreleased**: Compares discovered builds against `config/releases.yaml` to identify new releases.
- **Staging Download**: Downloads target artifacts (`bzImage`, `.config`, `lakitu_defconfig`, `COMMIT_INFO`, `vmlinux.gz`) for both the standard and KASAN builds into `data/staging/<release_id>/`.
- **Schedule Update**: Appends new target configurations to `config/releases.yaml` with `release-date` set to Wednesday 12:00 UTC.
- **Dry-Run Validation**: Executes `tools/activate_releases.py` in dry-run mode to verify:
  - Required kernel configuration options match specification (`tools/kernel_configs/lts-6.12-v2.config` or `tools/kernel_configs/hardened-v1.config`).
  - Remote HTTP HEAD checks for all artifacts succeed.
- **Maintainer Alert**: Sends an internal notification via Google Chat containing the prepared Discord announcement.
- **State Recorded**: Updates `config/auto_release.yaml` with `downloaded: true`.

---

### 2. Week 1: Wednesday 12:00 UTC — Promotion & Public Announcement
- **Activation**: Invokes `tools/activate_releases.py` to copy verified releases from `data/staging/<release_id>/` to production `data/releases/<release_id>/`.
- **Discord Announcement**: Posts to the public Discord webhook:
  > *"Hey! We are releasing target(s): `lts-6.12.X`. The evaluation slot opens next Monday (`YYYY-MM-DDT12:00:00Z`) and closes on Friday (`YYYY-MM-DDT12:00:00Z`)."*
- **Advance Notice**: Gives researchers and participants **5 days advance notice** before the evaluation slot opens.
- **State Recorded**: Updates `config/auto_release.yaml` with `activated: true`.

---

### 3. Week 2: Monday 12:00 UTC to Friday 12:00 UTC — Evaluation Window
- **Slot Opening**: On Monday at 12:00 UTC, the submission window opens automatically based on `server.py`'s `get_submission_window(release_date)`.
- **Exploit Evaluation**: Participants evaluate privilege escalation exploits through `client/cli.py exploit_binary --action evaluate`.
- **Flag Signing**: Successful evaluations during this window receive cryptographically signed HMAC-SHA1 verification flags.
- **Slot Closing**: On Friday at 12:00 UTC, the evaluation window closes.

---

## State & Directory Structure

| Path | Purpose |
| :--- | :--- |
| `config/auto_release.yaml` | Persistent state recording past and upcoming release cycles. |
| `config/releases.yaml` | Active kernel targets and their release dates. |
| `data/staging/` | Temporary download area for new releases before activation. |
| `data/releases/` | Production kernel builds used by `server.py` and QEMU VMs. |
| `tools/kernel_configs/` | Required `.config` files for pre-release validation. |

---

## Configuration & Credentials

The automation requires the following credentials in `secrets/`:
- `secrets/kernelctf-vm-reader-sa-key.json`: Google Cloud service account key with GCS read access.
- `secrets/server_secrets.py`:
  - `webhook_url`: Google Chat incoming webhook URL for maintainer alerts.
  - `discord_webhook_url`: Discord incoming webhook URL for public announcements.

---

## Manual Execution & Testing

```bash
# Run auto_release in development mode (skips webhook dispatch)
python3 tools/auto_release.py --devel

# Manually test release activation dry-run for a specific release
python3 tools/activate_releases.py --releases lts-6.12.104

# Validate kernel config against requirements
python3 tools/check_required_config.py data/staging/lts-6.12.104/.config tools/kernel_configs/lts-6.12-v2.config

# Run auto-release unit test suite
python3 -m unittest tests/test_auto_release.py
```
