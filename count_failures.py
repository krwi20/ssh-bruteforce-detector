

#!/usr/bin/env python3
# Day 1: count failed SSH logins by IP (simple version)

# New Words:
# - "open()" opens a file so Python can read it
# - "for line in file" reads one line at a time (efficient)
# - "in" checks if a phrase exists in a string
# - "split()" breaks a string into words (list) on whitespace
# - "dictionary" (dict) stores key->value pairs, e.g. {"203.0.113.10": 3}

import re
import argparse
from datetime import datetime, timedelta

#
def parse_ts(line: str) -> datetime | None:
    """
    Extract 'Sep 13 16:01:10' from the start of the line and turn it into a datetime
    We attach the current year because auth.log lines usually don't include it
        Returns None if parsing fails
    """
    try:
        # first 3 "words" are like: Sep 13 16:01:10
        ts_str = " ".join(line.split()[:3])
        year = datetime.now().year
        return datetime.strptime(f"{year} {ts_str}", "%Y %b %d %H:%M:%S")
    except Exception:
        return None

def detect_bursts(times_by_ip: dict[str, list[datetime]],
                    window_minutes: int,
                    threshold: int) -> dict[str, tuple[int, datetime, datetime]]:
    """
    For each IP check if there exists a time window of 'window_minutes'
    that contains at least 'threshold' failures
    Returns { ip: (count_in_window, first_ts, last_ts) } for flagged IPs
    """
    flagged = {}
    window = timedelta(minutes=window_minutes)

    for ip, ts_list in times_by_ip.items():
        if len(ts_list) < threshold:
            continue  # can't hit the threshold anyway

        ts = sorted(ts_list)  # ensure time order
        left = 0
        # Move 'right' forward one by one
        for right in range(len(ts)):
            # shrink from the left while the window is too big
            while ts[right] - ts[left] > window:
                left += 1

            # now ts[left]..ts[right] fits within the window
            count = right - left + 1
            if count >= threshold:
                # we found a burst; record once and move on
                flagged[ip] = (count, ts[left], ts[right])
                break

    return flagged

def parse_args():
    # create a parser with a one-line description
    p = argparse.ArgumentParser(
        description="Count SSH failed logins by IP and detect bursts (>= N in M minutes.)"
    )

    # -f / --file : which log file to read
    p.add_argument(
        "-f", "--file",
        default="auth_sample.log",
        help="Path to auth log (default: auth_sample.log)"
    )

    p.add_argument(
        "--top",
        type=int,
        default=10,
        help="How many rows to show per section (default: 10)"
    )
    # --window : minutes in the time window (int)
    p.add_argument(
        "--window",
        type=int,
        default=5,
        help="Time window is in minutes (default: 5)"
    )

    # --threshold : how many fails inside the window to flag (int)
    p.add_argument(
        "--threshold",
        type=int,
        default=3,
        help="Minimum failures inside window to flag (default: 3)"
    )

    return p.parse_args()

# One regex to grab username + IP from a "Failed password..." line
RE_FAIL = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>(?:\d{1,3}\.){3}\d{1,3})"
)

args = parse_args()
log_path = args.file
counts = {}       # empty dictionary to collect IP -> number of failures
times = {}        # IP -> list of timestamps
user_counts = {}  # username -> number of failed attempts

# Open the file (read-only, text mode)
with open(log_path, "r", encoding="utf-8", errors="replace") as fh:
    for line in fh:
        # keep only lines that contain the phrase 'Failed password'
        if "Failed password" not in line:
            continue

        # Try regex first (robust). If it matches, we get both username and IP
        m = RE_FAIL.search(line)
        if m:
            ip = m.group("ip")
            username = m.group("user")

            # count per IP
            counts[ip] = counts.get(ip, 0) + 1

            # timestamps per IP
            ts = parse_ts(line)
            if ts is not None:
                times.setdefault(ip, []).append(ts)

            # count per username
            if username:
                user_counts[username] = user_counts.get(username, 0) + 1

            # we are done for this line; skip the older split-based parsing
            continue

        # naive IP extraction:
        # sshd writes "... from <IP> port <NUMBER> ..."
        # so we split the line into words and find the word after 'from'
        parts = line.split()
        # defensive: check that 'from' appears and there IS a word after it
        if "from" in parts:
            idx = parts.index("from")
            if idx + 1 < len(parts):
                ip = parts[idx + 1]
                # bump the counter for this IP in the dict
                counts[ip] = counts.get(ip, 0) + 1

                # parse and store the timestamp under this IP
                ts = parse_ts(line)
                if ts is not None:
                    times.setdefault(ip, []).append(ts)

        # -- username extraction no regex ---
        # patterns:
        # A) "Failed password for root from ..."
        # B) "Failed password for invalid user bob from ..."
        username = None
        if "for" in parts:
            j = parts.index("for")
            # pattern A: username right after 'for'
            if j + 1 < len(parts) and parts[j + 1] != "invalid":
                username = parts[j + 1]
            # pattern B: "for invalid user"
            elif (j + 3 < len(parts)
                    and parts[j + 1] == "invalid"
                    and parts[j + 2] == "user"):
                username = parts[j + 3]

        # bump the username counter if we found one
        if username:
            user_counts[username] = user_counts.get(username, 0) + 1

WINDOW_MIN = args.window  # min
THRESHOLD = args.threshold  # attempts

bursts = detect_bursts(times, WINDOW_MIN, THRESHOLD)

# Print a tiny report (sorted by highest count)
print("=== SSH Failed Password Summary (simple) ===")
print(f"Source file: {log_path}")
print(f"Window/Thresh : {WINDOW_MIN} min / {THRESHOLD} fails")

if not counts:
    print("No failed logins found.")
else:
    for ip, c in sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:args.top]:
        first_last = ""
        if ip in times and times[ip]:
            first_seen = min(times[ip])
            last_seen = max(times[ip])
            first_last = f"  (first: {first_seen.strftime('%H:%M:%S')}, last: {last_seen.strftime('%H:%M:%S')})"
        print(f"{ip:<15} {c}{first_last}")

print(f"\n=== Bursts (>={THRESHOLD} fails in {WINDOW_MIN} min) ===")
if not bursts:
    print("None")
else:
    # sort by count descending
    for ip, (count, first_ts, last_ts) in sorted(
        bursts.items(), key=lambda kv: kv[1][0], reverse=True
    ):
        span = (last_ts - first_ts).total_seconds()
        print(f"{ip:<15} {count} in {span:.0f}s "
                f"(from {first_ts.strftime('%H:%M:%S')} to {last_ts.strftime('%H:%M:%S')})")

print("\n=== Top usernames (failed logins) ===")
if not user_counts:
    print("None")
else:
    for uname, c in sorted(user_counts.items(), key=lambda kv: kv[1], reverse=True)[:args.top]:
        print(f"{uname:<15} {c}")

ts = datetime.now().strftime("%Y%m%d-%H%M%S")
outname = f"report_ssh_{ts}.txt"

with open(outname, "w", encoding="utf-8") as out:
    out.write("SSH failed login summary\n")
    out.write(f"Source file : {log_path}\n")
    out.write(f"Window/Thresh : {WINDOW_MIN} min / {THRESHOLD} fails\n")
    out.write(f"Generated : {datetime.now().isoformat()}\n\n")

    # Section 1: IP Counts
    out.write("[Top IPs]\nIP, Count, First, Last\n")
    for ip, c in sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:args.top]:
        if ip in times and times[ip]:
            first_seen = min(times[ip]).strftime("%H:%M:%S")
            last_seen = max(times[ip]).strftime("%H:%M:%S")
        else:
            first_seen = last_seen = "-"
        out.write(f"{ip}, {c}, {first_seen}, {last_seen}\n")

    # Section 2: Bursts
    out.write("\n[Bursts]\nIP, CountInWindow, First, Last, SpanSeconds\n")
    if not bursts:
        out.write("None\n")
    else:
        for ip, (count, first_ts, last_ts) in sorted(
            bursts.items(), key=lambda kv: kv[1][0], reverse=True
        )[:args.top]:
            span = (last_ts - first_ts).total_seconds()
            out.write(f"{ip}, {count}, {first_ts:%H:%M:%S}, {last_ts:%H:%M:%S}, {span:.0f}\n")

    # Section 3: Usernames
    out.write("\n[Top usernames]\nUsername, Count\n")
    if not user_counts:
        out.write("None\n")
    else:
        for uname, c in sorted(user_counts.items(), key=lambda kv: kv[1], reverse=True)[:args.top]:
            out.write(f"{uname}, {c}\n")

print(f"\n(Report saved to {outname})")



