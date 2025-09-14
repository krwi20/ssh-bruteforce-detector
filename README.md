# SSH Brute-Force Detector (beginner-friendly)

A small Python tool that scans SSH authentication logs, counts **failed logins by IP**, detects **bursts** (>= _N_ failures in _M_ minutes), and shows **top usernames** tried. Designed for learning: simple code, step-by-step features.

> **Ethical use only.** Analyze your **own** log data or data you’re allowed to process.

## Features (current)
- Count failed SSH logins per **IP**.
- Track **first/last** time each IP failed.
- Detect bursts: **>= `--threshold`** failures in **`--window`** minutes (sliding window).
- Tally **usernames** from lines like:
  - `Failed password for root from …`
  - `Failed password for invalid user bob from …`
- Save a timestamped **report** file.
- Beginner-friendly code with clear steps.

## Requirements
- Python 3 (standard library only: `argparse`, `datetime`, `re`).

## Usage
From the project folder:
```bash
python3 count_failures.py -f auth_sample.log --window 5 --threshold 3 --top 10
```

### Arguments
- `-f, --file` — path to the log file (default: `auth_sample.log`)
- `--window` — time window in minutes for burst detection (default: `5`)
- `--threshold` — minimum failures within the window to flag (default: `3`)
- `--top` — how many rows to display per section (default: `10`)

## Example (your actual run)
```
=== SSH Failed Password Summary (simple) ===
Source file: auth_sample.log
Window/Thresh : 5 min / 3 fails
203.0.113.10    3  (first: 16:01:10, last: 16:01:30)
198.51.100.7    2  (first: 16:01:15, last: 16:01:25)
192.0.2.9       1  (first: 16:01:35, last: 16:01:35)

=== Bursts (>=3 fails in 5 min) ===
203.0.113.10    3 in 20s (from 16:01:10 to 16:01:30)

=== Top usernames (failed logins) ===
root            2
test            2
bob             1
admin           1

(Report saved to report_ssh_20250914-154829.txt)
```

## Getting log data (two easy options)
- **Sample file (learning):** edit `auth_sample.log` and re-run the script.
- **Real data (export first):**
  ```bash
  # if /var/log/auth.log exists
  sudo grep -i "failed password" /var/log/auth.log > auth_sample.log

  # or with systemd journal
  sudo journalctl -u ssh -n 1000 | grep -i "failed password" > auth_sample.log
  ```
  Then run:
  ```bash
  python3 count_failures.py -f auth_sample.log
  ```

## Output report
Script saves `report_ssh_YYYYMMDD-HHMMSS.txt` with:
- Top IPs (`count`, first/last seen)
- Bursts (count in window, first/last, span seconds)
- Top usernames

## Roadmap (small next steps)
- Optional CSV export (`--csv`)
- IPv6 support (pattern addition)
- Focus view (`--focus-ip`) to print a timeline for one IP

## License
MIT
