# Datasets

Spoor's accuracy is measured against a **public DFIR case with a published answer
key**, so findings are gradeable and the demo is reproducible. **No evidence images
or malware are committed** — only fetch instructions, hashes, and our *derived*
ground truth.

## Primary — DFIR Madness, Case 001: "The Stolen Szechuan Sauce"

| | |
|---|---|
| **Source** | https://dfirmadness.com/the-stolen-szechuan-sauce/ |
| **Answer key** | https://dfirmadness.com/answers-to-szechuan-case-001/ |
| **Evidence** | Windows **memory** + **E01 disk** + pagefile + **PCAP**, across two hosts |
| **Hosts** | `DC01` (Win Server 2012 R2, Domain Controller, `10.42.85.10`) · `DESKTOP-SDN1RPT` (Win 10) |
| **License** | Free/public for research. Redistribution terms unconfirmed → we ship **only our derived ground truth + this link**, never the images. |

### The known "evil" (ground truth)
- External attacker **`194.61.24.102`** brute-forces `Administrator` on **DC01** via **Hydra** (RDP).
- Malware **`C:\Windows\System32\coreupdate.exe`** downloaded over **HTTP @ 02:24:06**.
- Exfil archives **`secret.zip` @ ~02:31** and **`loot.zip` @ ~02:48**.

Machine-gradeable form: [`case001_ground_truth.json`](./case001_ground_truth.json). It is
derived from the published *narrative* answer key (fetched 2026-06-09) — **verify and
expand against the source before a final scored run.**

### Fetch (not committed)
```bash
# Download the archives from dfirmadness.com (see Source), then:
#   - extract/mount each READ-ONLY under $EVIDENCE_ROOT (e.g. /cases/case001)
#   - record the SHA256 of each archive below (evidence-integrity baseline)
```

| Archive | SHA256 |
|---|---|
| DC01-E01.zip | _fill after download_ |
| DC01-memory.zip | _fill after download_ |
| DESKTOP-E01.zip | _fill after download_ |
| DESKTOP-SDN1RPT-memory.zip | _fill after download_ |
| case001-pcap.zip | _fill after download_ |

## Fallback (zero-friction)
A public Volatility 3 sample memory image
(<https://github.com/volatilityfoundation/volatility/wiki/Memory-Samples>) for the
memory-only path, if the full case is unavailable.
