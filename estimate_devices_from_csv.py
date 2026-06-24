#!/usr/bin/env python3
"""
device_estimator.py — Physical device and people estimator
-----------------------------------------------------------
Reads a CSV produced by wifi_sniffer.py and estimates:
  1. How many unique physical devices were present
     (collapsing randomized-MAC rotations into one device)
  2. How many people that likely represents

Method overview
---------------
Each row in the CSV is a MAC address. For randomized MACs, one physical
device can appear as multiple rows (MAC rotations). We detect rotations by
scoring every pair of client MACs on six signals:

  Signal                  What it tells us
  ──────────────────────  ──────────────────────────────────────────────────
  IE fingerprint match    Same chipset/OS class — necessary but not sufficient
  Probe SSID overlap      Same saved-network history — strong personal signal
  RSSI similarity         Similar physical position in the room
  Vendor match            Same manufacturer — weak alone, supports other signals
  Vendor IE overlap       Same internal OUI tags — more specific than vendor name
  Temporal exclusivity    Active at the same time → CANNOT be same device (veto)

Each signal contributes a partial score. Scores sum to a confidence value
between 0.0 and 1.0. Pairs above MERGE_THRESHOLD are considered the same
physical device and merged in a graph. Connected components of that graph
are the estimated physical devices.

Usage
-----
  python3 device_estimator.py results.csv
  python3 device_estimator.py results.csv --threshold 0.6
  python3 device_estimator.py results.csv --devices-per-person 1.8 --verbose
  python3 device_estimator.py results.csv --rssi-tolerance 8

All thresholds are configurable via CLI flags — see --help.
"""

import argparse
import csv
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path


# ═══════════════════════════════════════════════════════════════════
# SCORING WEIGHTS
# How much each signal contributes to the total merge confidence.
# All weights must sum to 1.0.
# Adjust here if you want to emphasise certain signals for your environment.
# ═══════════════════════════════════════════════════════════════════

W_IE_FINGERPRINT = 0.35   # IE fingerprint exact match
W_PROBE_SSID     = 0.30   # Probe SSID set overlap (Jaccard similarity)
W_RSSI           = 0.15   # RSSI proximity
W_VENDOR         = 0.10   # Same manufacturer name
W_VENDOR_IE      = 0.10   # Vendor-specific IE OUI overlap


# ═══════════════════════════════════════════════════════════════════
# DATA LOADING
# ═══════════════════════════════════════════════════════════════════

def parse_time(t: str):
    """
    Parse a time string from the CSV first_seen / last_seen columns.
    The sniffer writes these as "HH:MM:SS" (no date).
    Returns a datetime on an arbitrary fixed date — we only care about
    the relative differences between times, not the absolute date.
    """
    if not t:
        return None
    try:
        return datetime.strptime(t.strip(), "%H:%M:%S")
    except ValueError:
        return None


def parse_set(value: str) -> set:
    """
    Parse a semicolon-separated string from the CSV into a Python set.
    Empty strings return an empty set.

    Used for probe_ssids, frame_types, and vendor_ies columns.
    """
    if not value or not value.strip():
        return set()
    return {item.strip() for item in value.split(";") if item.strip()}


def load_csv(filepath: str) -> list[dict]:
    """
    Load the CSV and return a list of dicts, one per client device row.

    Filtering applied here:
      - Rows where type == "Access Point" are dropped — APs are not people.
      - Rows with no MAC address are dropped (malformed).
      - All string columns are stripped of whitespace.
      - Typed columns (rssi_dbm, distance_m, packet_count, mac_randomized)
        are converted to the correct Python types.
    """
    rows = []
    filepath = Path(filepath)

    if not filepath.exists():
        print(f"[!] File not found: {filepath}")
        sys.exit(1)

    with open(filepath, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)

        # Verify this CSV matches our expected format
        required = {"mac", "type", "ie_fingerprint", "probe_ssids",
                    "rssi_dbm", "vendor", "first_seen", "last_seen"}
        missing  = required - set(reader.fieldnames or [])
        if missing:
            print(f"[!] CSV is missing expected columns: {missing}")
            print(f"    Make sure this CSV was produced by wifi_sniffer.py")
            sys.exit(1)

        for row in reader:
            # Drop access points
            if row.get("type", "").strip() == "Access Point":
                continue

            mac = row.get("mac", "").strip()
            if not mac:
                continue

            # ── Type conversions ──────────────────────────────────────────
            # rssi_dbm: integer, or None if the column is empty
            try:
                rssi_val = row.get("rssi_dbm") or ""
                rssi = int(rssi_val) if rssi_val.strip() else None
            except (ValueError, KeyError):
                rssi = None

            # distance_m: float, or None
            try:
                dist_val = row.get("distance_m") or ""
                dist = float(dist_val) if dist_val.strip() else None
            except (ValueError, KeyError):
                dist = None

            # packet_count: integer, or 0
            try:
                pkt_val = row.get("packet_count") or ""
                pkt_count = int(pkt_val) if pkt_val.strip() else 0
            except (ValueError, KeyError):
                pkt_count = 0

            # mac_randomized: bool — CSV stores "True"/"False" strings
            rand_str = (row.get("mac_randomized") or "").strip().lower()
            randomized = rand_str == "true"

            rows.append({
                "mac":            mac,
                "randomized":     randomized,
                "vendor":         (row.get("vendor") or "").strip(),
                "ie_fingerprint": (row.get("ie_fingerprint") or "").strip(),
                "ie_sequence":    (row.get("ie_sequence") or "").strip(),
                "probe_ssids":    parse_set(row.get("probe_ssids") or ""),
                "vendor_ies":     parse_set(row.get("vendor_ies") or ""),
                "rssi_dbm":       rssi,
                "distance_m":     dist,
                "zone":           (row.get("zone") or "").strip(),
                "packet_count":   pkt_count,
                "frame_types":    parse_set(row.get("frame_types") or ""),
                "first_seen":     parse_time(row.get("first_seen") or ""),
                "last_seen":      parse_time(row.get("last_seen") or ""),
                "scan_start":     (row.get("scan_start") or "").strip(),
            })

    return rows


# ═══════════════════════════════════════════════════════════════════
# INDIVIDUAL SIGNAL SCORERS
# Each function takes two device dicts and returns a float 0.0–1.0.
# 0.0 = no similarity, 1.0 = identical on this signal.
# ═══════════════════════════════════════════════════════════════════

def score_ie_fingerprint(a: dict, b: dict) -> float:
    """
    Exact match on IE fingerprint hash.

    Returns 1.0 if both have the same non-empty fingerprint, else 0.0.
    This is binary — either the IE sequence matches exactly or it doesn't.

    Caveat: same fingerprint does NOT mean same physical device — it means
    same chipset/OS/driver version. Treated as necessary but not sufficient.
    """
    fp_a = a["ie_fingerprint"]
    fp_b = b["ie_fingerprint"]
    if not fp_a or not fp_b:
        return 0.0
    return 1.0 if fp_a == fp_b else 0.0


def score_probe_ssids(a: dict, b: dict) -> float:
    """
    Jaccard similarity of the two probe SSID sets.

    Jaccard = |intersection| / |union|
    Range: 0.0 (no shared SSIDs) to 1.0 (identical SSID sets).

    This is the strongest personal signal: the probe SSID list reflects
    which networks a device has historically connected to. Two devices
    probing for the same set of SSIDs almost certainly belong to the same
    person, or in the extreme case, the same rotating physical device.

    Edge cases:
      - Both sets empty → 0.0 (no information, don't reward)
      - One set empty   → 0.0 (can't compare)
    """
    s_a = a["probe_ssids"]
    s_b = b["probe_ssids"]
    if not s_a or not s_b:
        return 0.0
    intersection = len(s_a & s_b)
    union        = len(s_a | s_b)
    return intersection / union if union > 0 else 0.0


def score_rssi(a: dict, b: dict, tolerance: int = 5) -> float:
    """
    Score based on how similar the two devices' RSSI values are.

    RSSI is a proxy for physical position — two readings of the same device
    at different times should be similar (within ±5–10 dBm of each other).
    Two readings from different devices at different positions will likely
    be more different.

    Scoring curve:
      delta <= 0           → 1.0  (identical)
      delta <= tolerance   → linear decay from 1.0 to 0.5
      delta <= tolerance*2 → linear decay from 0.5 to 0.0
      delta > tolerance*2  → 0.0  (too different to be meaningful)

    `tolerance` is configurable via --rssi-tolerance (default 5 dBm).

    Important: RSSI naturally fluctuates ±5–10 dBm even for a stationary
    device (multipath, body absorption, interference). So "similar RSSI"
    is supporting evidence only, never conclusive on its own.
    """
    if a["rssi_dbm"] is None or b["rssi_dbm"] is None:
        return 0.0

    delta = abs(a["rssi_dbm"] - b["rssi_dbm"])

    if delta <= tolerance:
        # Close to identical — score between 1.0 and 0.5
        return 1.0 - 0.5 * (delta / tolerance)
    elif delta <= tolerance * 2:
        # Moderate difference — score between 0.5 and 0.0
        return 0.5 - 0.5 * ((delta - tolerance) / tolerance)
    else:
        return 0.0


def score_vendor(a: dict, b: dict) -> float:
    """
    Binary match on vendor name string.

    Same non-empty vendor → 1.0, otherwise 0.0.
    Vendor alone is a very weak signal (many people own the same brand),
    but it supports other signals — you can't merge across brands.
    """
    v_a = a["vendor"]
    v_b = b["vendor"]
    if not v_a or not v_b:
        return 0.0
    return 1.0 if v_a == v_b else 0.0


def score_vendor_ies(a: dict, b: dict) -> float:
    """
    Jaccard similarity of the vendor-specific IE OUI sets.

    Vendor IEs (ID=221 elements) contain OUIs identifying which company
    defined that extension — e.g. 00:50:f2 = Microsoft WMM/WPS,
    or a phone manufacturer's proprietary tag. These are more specific
    than just the vendor name and complement the IE fingerprint score.
    """
    s_a = a["vendor_ies"]
    s_b = b["vendor_ies"]
    if not s_a or not s_b:
        return 0.0
    intersection = len(s_a & s_b)
    union        = len(s_a | s_b)
    return intersection / union if union > 0 else 0.0


# ═══════════════════════════════════════════════════════════════════
# TEMPORAL VETO
# This is NOT a scoring signal — it's a hard constraint.
# ═══════════════════════════════════════════════════════════════════

def temporal_overlap(a: dict, b: dict) -> bool:
    """
    Return True if devices A and B were active at the same time.

    One physical radio can only transmit on one MAC address at a time.
    If two MACs have overlapping active windows, they CANNOT be the same
    physical device — regardless of how similar their other signals are.

    This is the most reliable signal in the whole pipeline because it's
    based on a hard physical constraint, not a probabilistic pattern.

    "Active window" = [first_seen, last_seen] for each device.
    Overlap exists if one window starts before the other ends.
    """
    if not all([a["first_seen"], a["last_seen"],
                b["first_seen"], b["last_seen"]]):
        # Missing timestamps — can't apply the veto, allow scoring to proceed
        return False

    # Two intervals [s1, e1] and [s2, e2] overlap if s1 < e2 AND s2 < e1
    return (a["first_seen"] < b["last_seen"] and
            b["first_seen"] < a["last_seen"])


# ═══════════════════════════════════════════════════════════════════
# PAIRWISE SCORING
# ═══════════════════════════════════════════════════════════════════

def compute_similarity(a: dict, b: dict, rssi_tolerance: int) -> tuple[float, dict]:
    """
    Compute total merge confidence between two device records.

    Returns
    -------
    total_score : float
        Weighted sum of all signal scores, 0.0–1.0.
        Forced to 0.0 if temporal overlap veto fires.
    breakdown   : dict
        Individual signal scores for transparency in verbose output.
    """
    breakdown = {}

    # ── Hard veto first ──────────────────────────────────────────────────────
    if temporal_overlap(a, b):
        # These two MACs were active simultaneously — they cannot be the same
        # device. Override everything else and return 0.
        breakdown["temporal_veto"] = True
        return 0.0, breakdown

    breakdown["temporal_veto"] = False

    # ── Individual signal scores ─────────────────────────────────────────────
    breakdown["ie_fingerprint"] = score_ie_fingerprint(a, b)
    breakdown["probe_ssids"]    = score_probe_ssids(a, b)
    breakdown["rssi"]           = score_rssi(a, b, rssi_tolerance)
    breakdown["vendor"]         = score_vendor(a, b)
    breakdown["vendor_ies"]     = score_vendor_ies(a, b)

    # ── Weighted total ───────────────────────────────────────────────────────
    total = (
        W_IE_FINGERPRINT * breakdown["ie_fingerprint"] +
        W_PROBE_SSID     * breakdown["probe_ssids"]    +
        W_RSSI           * breakdown["rssi"]           +
        W_VENDOR         * breakdown["vendor"]         +
        W_VENDOR_IE      * breakdown["vendor_ies"]
    )

    return round(total, 4), breakdown


# ═══════════════════════════════════════════════════════════════════
# GRAPH — UNION-FIND (connected components)
# ═══════════════════════════════════════════════════════════════════

class UnionFind:
    """
    Union-Find (Disjoint Set Union) data structure.

    Used to group MAC addresses into clusters where each cluster
    represents one physical device.

    How it works:
      - Each MAC starts as its own group (parent of itself).
      - When we decide two MACs are "probably the same device", we call
        union(mac_a, mac_b) to merge their groups.
      - find(mac) returns the "root" representative of that group —
        any MAC in the same group returns the same root.
      - The number of unique roots at the end = number of physical devices.

    Path compression (in find) and union by rank keep operations fast
    even with hundreds of devices.
    """

    def __init__(self, items: list[str]):
        self.parent = {item: item for item in items}
        self.rank   = {item: 0    for item in items}

    def find(self, x: str) -> str:
        """Find root of x's group, with path compression."""
        if self.parent[x] != x:
            self.parent[x] = self.find(self.parent[x])   # path compression
        return self.parent[x]

    def union(self, x: str, y: str) -> None:
        """Merge the groups containing x and y."""
        rx, ry = self.find(x), self.find(y)
        if rx == ry:
            return   # already in the same group
        # Union by rank: attach smaller tree under larger to keep tree flat
        if self.rank[rx] < self.rank[ry]:
            rx, ry = ry, rx
        self.parent[ry] = rx
        if self.rank[rx] == self.rank[ry]:
            self.rank[rx] += 1

    def groups(self) -> dict[str, list[str]]:
        """Return {root: [all MACs in this group]} for all groups."""
        result = defaultdict(list)
        for item in self.parent:
            result[self.find(item)].append(item)
        return dict(result)


# ═══════════════════════════════════════════════════════════════════
# CLUSTERING
# ═══════════════════════════════════════════════════════════════════

def cluster_devices(
    rows: list[dict],
    threshold: float,
    rssi_tolerance: int,
    verbose: bool
) -> tuple[dict, list[tuple]]:
    """
    Compare every pair of client devices and merge those above threshold.

    Returns
    -------
    groups : dict
        {root_mac: [list of MACs in this cluster]}
    scored_pairs : list of tuples
        Every pair that was scored, with score and breakdown — for reporting.
    """
    macs = [r["mac"] for r in rows]
    uf   = UnionFind(macs)

    # Build a lookup dict so we can access any row by MAC quickly
    by_mac = {r["mac"]: r for r in rows}

    scored_pairs = []

    # Compare every unique pair — O(n²) which is fine for typical scan sizes
    # (hundreds of devices at most; a room with 50 people might give ~100 MACs)
    for i in range(len(rows)):
        for j in range(i + 1, len(rows)):
            a = rows[i]
            b = rows[j]

            score, breakdown = compute_similarity(a, b, rssi_tolerance)
            scored_pairs.append((a["mac"], b["mac"], score, breakdown))

            if score >= threshold:
                uf.union(a["mac"], b["mac"])

    return uf.groups(), scored_pairs


# ═══════════════════════════════════════════════════════════════════
# CONFIDENCE ASSESSMENT
# ═══════════════════════════════════════════════════════════════════

def assess_confidence(rows: list[dict], groups: dict) -> tuple[str, list[str]]:
    """
    Assess how confident we are in the device count estimate.

    Confidence is reduced when:
      - Many devices share the same IE fingerprint (popular phone model —
        hard to distinguish individuals from rotations)
      - Many devices have no probe SSIDs (can't use the strongest signal)
      - Many devices have no RSSI (can't use position signal)
      - Scan duration was very short (fewer rotation cycles observed)

    Returns
    -------
    level   : str    — "high", "medium", or "low"
    reasons : list   — human-readable explanations of confidence reducers
    """
    reasons = []
    penalty = 0

    total = len(rows)
    if total == 0:
        return "low", ["No client devices found"]

    # ── IE fingerprint homogeneity ───────────────────────────────────────────
    # Count how many devices share each fingerprint. If one fingerprint
    # accounts for >40% of all devices, the environment has many identical
    # chipset/OS combos — hard to tell rotations from distinct devices.
    fp_counts = defaultdict(int)
    for r in rows:
        if r["ie_fingerprint"]:
            fp_counts[r["ie_fingerprint"]] += 1

    if fp_counts:
        max_fp_count = max(fp_counts.values())
        homogeneity  = max_fp_count / total
        if homogeneity > 0.5:
            reasons.append(
                f"{int(homogeneity*100)}% of devices share one IE fingerprint "
                f"(likely many same-model devices — rotation vs distinct device "
                f"distinction is unreliable)"
            )
            penalty += 2
        elif homogeneity > 0.3:
            reasons.append(
                f"{int(homogeneity*100)}% of devices share one IE fingerprint "
                f"(moderate device homogeneity)"
            )
            penalty += 1

    # ── Missing probe SSIDs ──────────────────────────────────────────────────
    no_probes = sum(1 for r in rows if not r["probe_ssids"])
    probe_miss_rate = no_probes / total
    if probe_miss_rate > 0.6:
        reasons.append(
            f"{int(probe_miss_rate*100)}% of devices have no probe SSIDs captured "
            f"(strongest individuating signal unavailable for most devices)"
        )
        penalty += 2
    elif probe_miss_rate > 0.3:
        reasons.append(
            f"{int(probe_miss_rate*100)}% of devices have no probe SSIDs"
        )
        penalty += 1

    # ── Missing RSSI ─────────────────────────────────────────────────────────
    no_rssi = sum(1 for r in rows if r["rssi_dbm"] is None)
    if no_rssi / total > 0.4:
        reasons.append(
            f"{int(no_rssi/total*100)}% of devices have no RSSI data "
            f"(position signal unavailable)"
        )
        penalty += 1

    # ── Single-packet devices ─────────────────────────────────────────────────
    # Devices seen only once give us very little signal to work with.
    single_pkt = sum(1 for r in rows if r["packet_count"] <= 1)
    if single_pkt / total > 0.4:
        reasons.append(
            f"{single_pkt} of {total} devices seen only once "
            f"(insufficient data to fingerprint confidently)"
        )
        penalty += 1

    # ── Determine level ──────────────────────────────────────────────────────
    if penalty == 0:
        level = "high"
    elif penalty <= 2:
        level = "medium"
    else:
        level = "low"

    if not reasons:
        reasons.append("All signals available, good device diversity")

    return level, reasons


# ═══════════════════════════════════════════════════════════════════
# REPORTING
# ═══════════════════════════════════════════════════════════════════

def print_report(
    rows:              list[dict],
    groups:            dict,
    scored_pairs:      list[tuple],
    confidence_level:  str,
    confidence_reasons:list[str],
    threshold:         float,
    devices_per_person:float,
    verbose:           bool,
) -> None:

    total_macs    = len(rows)
    total_devices = len(groups)
    rand_macs     = sum(1 for r in rows if r["randomized"])
    real_macs     = total_macs - rand_macs

    # Merged groups = clusters with more than one MAC (rotation detected)
    merged = {root: macs for root, macs in groups.items() if len(macs) > 1}
    solo   = {root: macs for root, macs in groups.items() if len(macs) == 1}

    # People estimate — apply floor/ceil for range
    import math
    raw_estimate    = total_devices / devices_per_person
    people_low      = max(1, math.floor(raw_estimate * 0.8))
    people_high     = math.ceil(raw_estimate * 1.2)
    people_midpoint = round(raw_estimate)

    print("\n" + "=" * 68)
    print("  DEVICE & PEOPLE ESTIMATOR REPORT")
    print("=" * 68)

    # ── Scan metadata ────────────────────────────────────────────────────────
    if rows:
        print(f"\n  Scan session : {rows[0].get('scan_start', 'N/A')}")

    # ── Raw MAC counts ───────────────────────────────────────────────────────
    print(f"\n  ── Raw MAC addresses (before deduplication) ──")
    print(f"  Total client MACs seen : {total_macs}")
    print(f"  Randomized MACs        : {rand_macs}  "
          f"({int(rand_macs/total_macs*100) if total_macs else 0}%)")
    print(f"  Real (OUI) MACs        : {real_macs}  "
          f"({int(real_macs/total_macs*100) if total_macs else 0}%)")

    # ── Clustering result ────────────────────────────────────────────────────
    print(f"\n  ── After clustering (merge threshold = {threshold}) ──")
    print(f"  Estimated physical devices : {total_devices}")
    print(f"  Merged groups (rotations)  : {len(merged)}  "
          f"({'groups where multiple MACs were collapsed into one device' if merged else 'none detected'})")
    print(f"  Solo MACs (unmerged)       : {len(solo)}")

    # ── Merged group details ─────────────────────────────────────────────────
    if merged:
        print(f"\n  ── Merged groups (probable MAC rotations) ──")
        for root, macs in sorted(merged.items(), key=lambda x: -len(x[1])):
            dev = rows[next(i for i, r in enumerate(rows) if r["mac"] == root)]
            print(f"\n  Group root : {root}")
            print(f"  MACs       : {', '.join(macs)}")
            print(f"  Vendor     : {dev['vendor'] or 'Unknown'}")
            print(f"  IE fp      : {dev['ie_fingerprint'] or 'N/A'}")
            shared_ssids = set.intersection(
                *[rows[next(i for i, r in enumerate(rows) if r["mac"] == m)]["probe_ssids"]
                  for m in macs]
            ) if len(macs) > 1 else set()
            if shared_ssids:
                print(f"  Shared probe SSIDs : {'; '.join(sorted(shared_ssids))}")

    # ── Confidence ───────────────────────────────────────────────────────────
    confidence_symbol = {"high": "●●●", "medium": "●●○", "low": "●○○"}
    print(f"\n  ── Confidence assessment ──")
    print(f"  Level  : {confidence_level.upper()}  {confidence_symbol.get(confidence_level, '')}")
    for reason in confidence_reasons:
        print(f"  Note   : {reason}")

    # ── People estimate ──────────────────────────────────────────────────────
    print(f"\n  ── People estimate ──")
    print(f"  Devices per person assumption : {devices_per_person}")
    print(f"  Raw estimate   : {raw_estimate:.1f}  ({total_devices} devices / {devices_per_person})")
    print(f"  Estimate range : {people_low} – {people_high} people")
    print(f"  Midpoint       : ~{people_midpoint} people")
    print()
    print(f"  ┌─────────────────────────────────────────────┐")
    print(f"  │  Estimated {people_low}–{people_high} people in the area")
    print(f"  │  ({total_devices} physical devices detected,")
    print(f"  │   confidence: {confidence_level.upper()})")
    print(f"  └─────────────────────────────────────────────┘")

    # ── Verbose: show top scoring pairs that were considered ─────────────────
    if verbose:
        print(f"\n  ── Top merge decisions (verbose) ──")
        print(f"  {'MAC A':<20} {'MAC B':<20} {'Score':>6}  "
              f"{'IE-FP':>5} {'Probe':>5} {'RSSI':>5} {'Vend':>5} {'VIE':>5} {'Veto':>5}")
        print(f"  {'-'*18:<20} {'-'*18:<20} {'-'*5:>6}  "
              f"{'-'*5:>5} {'-'*5:>5} {'-'*5:>5} {'-'*4:>5} {'-'*4:>5} {'-'*4:>5}")

        # Show all merged pairs first, then top non-merged pairs
        merged_pairs  = [(a, b, s, bd) for a, b, s, bd in scored_pairs if s >= threshold]
        near_pairs    = sorted(
            [(a, b, s, bd) for a, b, s, bd in scored_pairs if 0 < s < threshold],
            key=lambda x: -x[2]
        )[:10]

        for mac_a, mac_b, score, bd in merged_pairs + near_pairs:
            merged_marker = " ← merged" if score >= threshold else ""
            veto = "YES" if bd.get("temporal_veto") else "no"
            print(
                f"  {mac_a:<20} {mac_b:<20} {score:>6.3f}  "
                f"{bd.get('ie_fingerprint', 0):>5.2f} "
                f"{bd.get('probe_ssids',    0):>5.2f} "
                f"{bd.get('rssi',           0):>5.2f} "
                f"{bd.get('vendor',         0):>5.2f} "
                f"{bd.get('vendor_ies',     0):>5.2f} "
                f"{veto:>5}"
                f"{merged_marker}"
            )

    print("\n" + "=" * 68)
    print("  NOTE: This is a probabilistic estimate, not a precise count.")
    print("  Accuracy improves with longer scan duration, varied probe")
    print("  activity, and lower device model homogeneity in the environment.")
    print("=" * 68 + "\n")


# ═══════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════════════

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Estimate physical device count and people from wifi_sniffer.py CSV output",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 device_estimator.py 2026_06_17_14_32_00.csv
  python3 device_estimator.py scan.csv --threshold 0.55 --verbose
  python3 device_estimator.py scan.csv --devices-per-person 1.8 --rssi-tolerance 8
        """
    )
    parser.add_argument(
        "csv_file",
        help="Path to the CSV file produced by wifi_sniffer.py"
    )
    parser.add_argument(
        "--threshold", "-t",
        type=float, default=0.6,
        help=(
            "Merge confidence threshold (0.0–1.0). "
            "Two MACs scoring above this are treated as one physical device. "
            "Lower = more aggressive merging. Default: 0.6"
        )
    )
    parser.add_argument(
        "--devices-per-person", "-d",
        type=float, default=2.0,
        dest="devices_per_person",
        help=(
            "Average WiFi devices per person in your environment. "
            "Office: ~2.0  Classroom: ~1.5  Cafe: ~1.2  Default: 2.0"
        )
    )
    parser.add_argument(
        "--rssi-tolerance", "-r",
        type=int, default=5,
        dest="rssi_tolerance",
        help=(
            "RSSI tolerance in dBm for position similarity scoring. "
            "Higher = more lenient (accounts for signal fluctuation). "
            "Default: 5 dBm"
        )
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show detailed scoring breakdown for every considered MAC pair"
    )
    args = parser.parse_args()

    # Validate threshold range
    if not 0.0 < args.threshold < 1.0:
        print("[!] --threshold must be between 0.0 and 1.0 (exclusive)")
        sys.exit(1)

    print(f"[*] Loading      : {args.csv_file}")
    rows = load_csv(args.csv_file)

    if not rows:
        print("[!] No client device rows found in this CSV.")
        print("    The file may contain only Access Points, or may be empty.")
        sys.exit(0)

    print(f"[*] Client rows  : {len(rows)}")
    print(f"[*] Threshold    : {args.threshold}")
    print(f"[*] RSSI tol.    : ±{args.rssi_tolerance} dBm")
    print(f"[*] Dev/person   : {args.devices_per_person}")
    print(f"[*] Clustering...")

    groups, scored_pairs = cluster_devices(
        rows, args.threshold, args.rssi_tolerance, args.verbose
    )

    confidence_level, confidence_reasons = assess_confidence(rows, groups)

    print_report(
        rows, groups, scored_pairs,
        confidence_level, confidence_reasons,
        args.threshold, args.devices_per_person,
        args.verbose
    )


if __name__ == "__main__":
    main()