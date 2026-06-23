#!/usr/bin/env python3
"""
Estimate occupants from a wifi_sniffer.py CSV without changing the sniffer.

The sniffer records one row per source MAC. This post-processor keeps real
client MACs as one occupant each, then cautiously groups randomized client MACs
that look like sequential sessions from the same device.
"""

from __future__ import annotations

import argparse
import csv
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from config import CSV_FIELDS


GROUP_SCORE_THRESHOLD = 6
OVERLAP_TOLERANCE_SECONDS = 5


@dataclass(frozen=True)
class Observation:
    mac: str
    device_type: str
    randomized: bool
    rssi: int | None
    zone: str
    ie_fingerprint: str
    vendor_ies: frozenset[str]
    frame_types: frozenset[str]
    probe_ssids: frozenset[str]
    first_seen_s: int | None
    last_seen_s: int | None
    packet_count: int


@dataclass
class SessionGroup:
    observations: list[Observation] = field(default_factory=list)

    def add(self, obs: Observation) -> None:
        self.observations.append(obs)

    @property
    def macs(self) -> list[str]:
        return [obs.mac for obs in self.observations]

    @property
    def representative(self) -> Observation:
        return self.observations[-1]


def parse_bool(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "y"}


def parse_int(value: str) -> int | None:
    value = value.strip()
    if not value:
        return None
    try:
        return int(float(value))
    except ValueError:
        return None


def parse_time_to_seconds(value: str) -> int | None:
    value = value.strip()
    if not value:
        return None
    try:
        parsed = datetime.strptime(value, "%H:%M:%S")
    except ValueError:
        return None
    return parsed.hour * 3600 + parsed.minute * 60 + parsed.second


def parse_set(value: str) -> frozenset[str]:
    if not value:
        return frozenset()
    normalized = value.replace(",", ";")
    return frozenset(part.strip() for part in normalized.split(";") if part.strip())


def load_observations(csv_path: Path) -> list[Observation]:
    with csv_path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        missing = [name for name in CSV_FIELDS if name not in (reader.fieldnames or [])]
        if missing:
            raise ValueError(f"CSV is missing expected columns: {', '.join(missing)}")

        observations = []
        for row in reader:
            observations.append(
                Observation(
                    mac=row["mac"].strip().lower(),
                    device_type=row["type"].strip(),
                    randomized=parse_bool(row["mac_randomized"]),
                    rssi=parse_int(row["rssi_dbm"]),
                    zone=row["zone"].strip(),
                    ie_fingerprint=row["ie_fingerprint"].strip(),
                    vendor_ies=parse_set(row["vendor_ies"]),
                    frame_types=parse_set(row["frame_types"]),
                    probe_ssids=parse_set(row["probe_ssids"]),
                    first_seen_s=parse_time_to_seconds(row["first_seen"]),
                    last_seen_s=parse_time_to_seconds(row["last_seen"]),
                    packet_count=parse_int(row["packet_count"]) or 0,
                )
            )
    return observations


def is_client(obs: Observation) -> bool:
    return obs.device_type.lower() != "access point"


def sessions_overlap(left: Observation, right: Observation) -> bool:
    if None in {left.first_seen_s, left.last_seen_s, right.first_seen_s, right.last_seen_s}:
        return False

    left_start = left.first_seen_s or 0
    left_end = left.last_seen_s or left_start
    right_start = right.first_seen_s or 0
    right_end = right.last_seen_s or right_start

    return (
        left_start <= right_end + OVERLAP_TOLERANCE_SECONDS
        and right_start <= left_end + OVERLAP_TOLERANCE_SECONDS
    )


def time_gap_seconds(left: Observation, right: Observation) -> int | None:
    if None in {left.first_seen_s, left.last_seen_s, right.first_seen_s, right.last_seen_s}:
        return None

    left_start = left.first_seen_s or 0
    left_end = left.last_seen_s or left_start
    right_start = right.first_seen_s or 0
    right_end = right.last_seen_s or right_start

    if left_end <= right_start:
        return right_start - left_end
    if right_end <= left_start:
        return left_start - right_end
    return 0


def same_session_score(left: Observation, right: Observation) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []

    if left.ie_fingerprint and right.ie_fingerprint:
        if left.ie_fingerprint == right.ie_fingerprint:
            score += 3
            reasons.append("same IE fingerprint")
        else:
            score -= 3
            reasons.append("different IE fingerprint")

    if left.vendor_ies and right.vendor_ies:
        if left.vendor_ies & right.vendor_ies:
            score += 2
            reasons.append("vendor IE overlap")
        else:
            score -= 1

    if left.probe_ssids and right.probe_ssids:
        if left.probe_ssids & right.probe_ssids:
            score += 2
            reasons.append("probe SSID overlap")
        else:
            score -= 1

    if left.rssi is not None and right.rssi is not None:
        rssi_delta = abs(left.rssi - right.rssi)
        if rssi_delta <= 6:
            score += 2
            reasons.append("close RSSI")
        elif rssi_delta <= 10:
            score += 1
            reasons.append("similar RSSI")
        elif rssi_delta > 15:
            score -= 1

    if left.zone and right.zone and left.zone == right.zone:
        score += 1
        reasons.append("same zone")

    if left.frame_types and right.frame_types and left.frame_types & right.frame_types:
        score += 1
        reasons.append("frame type overlap")

    gap = time_gap_seconds(left, right)
    if gap is not None:
        if gap <= 120:
            score += 1
            reasons.append("nearby time window")
        elif gap > 1800:
            score -= 2

    return score, reasons


def can_merge_with_group(group: SessionGroup, obs: Observation) -> tuple[bool, int, list[str]]:
    if any(sessions_overlap(existing, obs) for existing in group.observations):
        return False, 0, ["overlapping randomized sessions"]

    best_score = -99
    best_reasons: list[str] = []
    for existing in group.observations:
        score, reasons = same_session_score(existing, obs)
        if score > best_score:
            best_score = score
            best_reasons = reasons

    if best_score < GROUP_SCORE_THRESHOLD:
        return False, best_score, best_reasons

    supporting_reasons = {
        "vendor IE overlap",
        "probe SSID overlap",
        "close RSSI",
        "similar RSSI",
        "same zone",
        "frame type overlap",
        "nearby time window",
    }
    support_count = len(supporting_reasons & set(best_reasons))
    return support_count >= 2, best_score, best_reasons


def group_randomized_clients(observations: list[Observation]) -> list[SessionGroup]:
    randomized = sorted(
        (obs for obs in observations if is_client(obs) and obs.randomized),
        key=lambda obs: (obs.first_seen_s is None, obs.first_seen_s or 0, obs.mac),
    )
    groups: list[SessionGroup] = []

    for obs in randomized:
        best_group: SessionGroup | None = None
        best_score = -99

        for group in groups:
            allowed, score, _ = can_merge_with_group(group, obs)
            if allowed and score > best_score:
                best_group = group
                best_score = score

        if best_group is None:
            groups.append(SessionGroup([obs]))
        else:
            best_group.add(obs)

    return groups


def estimate_occupancy(observations: list[Observation]) -> dict[str, object]:
    real_clients = [
        obs for obs in observations
        if is_client(obs) and not obs.randomized
    ]
    randomized_groups = group_randomized_clients(observations)

    return {
        "real_client_count": len(real_clients),
        "randomized_session_count": len(randomized_groups),
        "estimated_occupants": len(real_clients) + len(randomized_groups),
        "randomized_groups": randomized_groups,
    }


def print_report(result: dict[str, object], show_details: bool) -> None:
    print(f"Real client MACs       : {result['real_client_count']}")
    print(f"Randomized sessions    : {result['randomized_session_count']}")
    print(f"Estimated occupants    : {result['estimated_occupants']}")
    print(
        "\nMethod: real client MACs count directly; randomized MACs are grouped only "
        "when sessions do not overlap and several signals agree."
    )
    print(
        "Signals used: IE fingerprint, vendor IE OUIs, RSSI/zone similarity, "
        "frame types, probe SSIDs, and time gap."
    )
    print("Note: this estimates device occupancy; it does not identify a person.")

    if not show_details:
        return

    print("\nRandomized groups:")
    for index, group in enumerate(result["randomized_groups"], start=1):
        macs = ", ".join(group.macs)
        print(f"  {index}. {len(group.observations)} MAC(s): {macs}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Estimate occupancy from a wifi_sniffer.py CSV."
    )
    parser.add_argument("csv_path", type=Path, help="CSV generated by wifi_sniffer.py")
    parser.add_argument("--details", action="store_true", help="Show grouped randomized MACs")
    args = parser.parse_args()

    observations = load_observations(args.csv_path)
    result = estimate_occupancy(observations)
    print_report(result, args.details)


if __name__ == "__main__":
    main()
