#!/usr/bin/env python3
"""
Concentric-ring device density around a sensor.

Reads night_sniffer_v3 CSV output, buckets devices into distance annuli, and
renders one ring per bucket shaded by the number of distinct devices in it.

Deliberately radially symmetric. A single antenna yields no bearing, so the
plot must not imply one: every ring is uniform all the way round, and the
picture says exactly what the data says — how many devices, how far out, and
nothing about which way.

Reads only. Touches no capture code, no interface, no source file.

  python3 ring_density.py './csv_analyze/*-wifi_full_recon_report.csv'
  python3 ring_density.py 'logs/*.csv' --bands 3,7,12,20 --out rings.png
"""

import argparse
import glob
import sys

import duckdb
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Circle
from matplotlib.colors import Normalize
from matplotlib.cm import ScalarMappable

# Client-originated subtypes only. Beacons and Probe Responses come from APs,
# which sit at fixed distances and never move — including them would make the
# plot a picture of the building's infrastructure rather than of its people.
# Mirrors CLIENT_FRAME_TYPES in night_sniffer_v3.py; kept as a literal here so
# this script imports nothing from the capture tool.
CLIENT_FRAME_TYPES = (
    "PROBE", "ASSOC_REQ", "REASSOC_REQ", "AUTH", "DEAUTH", "DISASSOC",
)

# Outer edge of each ring, metres. Defaults follow proximity_zone().
DEFAULT_BANDS = [5.0, 10.0, 15.0, 40.0]


def load_counts(pattern: str, bands: list[float], since: str | None):
    """Return (labels, counts, total_macs, total_rows) for one CSV glob.

    A device is placed in exactly ONE ring, at the median of every distance
    estimate recorded for its MAC. Counting a MAC in every ring it ever
    appeared in would inflate the total well past the number of devices
    present — RSSI wanders several dB frame to frame, so a stationary phone
    produces distance estimates spread across two or three bands on its own.
    The median is the cheapest defensible summary of that spread.
    """
    files = sorted(glob.glob(pattern))
    if not files:
        sys.exit(f"No CSV files matched: {pattern}")

    con = duckdb.connect()
    # DuckDB will not bind a parameter inside CREATE VIEW, so the paths are
    # inlined. They come from glob() against the local filesystem, not from
    # anything captured, and single quotes are escaped.
    file_list = ",".join("'" + f.replace("'", "''") + "'" for f in files)
    con.execute(
        f"CREATE VIEW frames AS "
        f"SELECT * FROM read_csv_auto([{file_list}], union_by_name=true)"
    )

    where = [
        f"Pkt_Type IN ({','.join(repr(t) for t in CLIENT_FRAME_TYPES)})",
        "Distance_m IS NOT NULL",
        "Distance_m > 0",
        "MAC_Address IS NOT NULL",
        "MAC_Address <> ''",
    ]
    if since:
        where.append(f"Timestamp_ISO >= '{since}'")

    total_rows = con.execute(
        f"SELECT count(*) FROM frames WHERE {' AND '.join(where)}"
    ).fetchone()[0]

    # One row per MAC, at its median distance.
    per_mac = con.execute(f"""
        SELECT MAC_Address, median(Distance_m) AS d
        FROM frames
        WHERE {' AND '.join(where)}
        GROUP BY MAC_Address
    """).fetchall()

    counts = [0] * len(bands)
    for _mac, d in per_mac:
        for i, outer in enumerate(bands):
            if d <= outer:
                counts[i] += 1
                break
        # Anything past the outermost band is deliberately not counted. It is
        # reported as a dropped total on the plot rather than folded into the
        # last ring, where it would read as devices that are actually there.

    labels = []
    inner = 0.0
    for outer in bands:
        labels.append(f"{inner:g}\u2013{outer:g} m")
        inner = outer

    return labels, counts, len(per_mac), total_rows


def render(labels, counts, bands, out_path, title, total_macs, total_rows,
           scale="equal"):
    """Draw the rings. Colour is device count; radius encodes distance.

    ``scale`` chooses how distance maps to radius:

      "true"  — radius IS metres. Spatially faithful, but the outermost band
                is usually the widest in metres and so dominates the picture
                regardless of how few devices are in it.
      "equal" — every band gets the same ring width. Distances stop being to
                scale (the label on each ring says what it covers), and every
                band gets visual weight proportional to nothing but its own
                position, which is what makes the colour readable.

    Neither is more honest than the other; they mislead in different
    directions. "equal" is the default because the thing being read off this
    plot is the colour, not the geometry.
    """
    fig, (ax, cax) = plt.subplots(
        1, 2, figsize=(9, 7.5),
        gridspec_kw={"width_ratios": [20, 1]},
    )

    peak = max(counts) if any(counts) else 1
    norm = Normalize(vmin=0, vmax=peak)
    cmap = plt.get_cmap("inferno")

    inner_edges = [0.0] + bands[:-1]
    if scale == "true":
        radii = list(bands)
    else:
        radii = [i + 1 for i in range(len(bands))]
    inner_radii = [0.0] + radii[:-1]

    # Outermost first so inner rings paint on top.
    for r, n in sorted(zip(radii, counts), key=lambda t: -t[0]):
        ax.add_patch(Circle((0, 0), r, facecolor=cmap(norm(n)),
                            edgecolor="#ffffff", linewidth=1.2, zorder=1))

    for r, r_in, n, label in zip(radii, inner_radii, counts, labels):
        mid = (r + r_in) / 2
        # Innermost label sits above the sensor marker rather than on it.
        y = mid if r_in > 0 else r * 0.55
        ax.text(0, y, f"{n}", ha="center", va="center",
                color="#ffffff" if norm(n) < 0.6 else "#000000",
                fontsize=13, fontweight="bold", zorder=3)
        ax.text(mid * 0.72, -mid * 0.72, label, ha="center", va="center",
                color="#dddddd" if norm(n) < 0.6 else "#333333",
                fontsize=8, zorder=3)

    # The sensor.
    ax.plot(0, 0, marker="s", markersize=9, color="#e8e8e8",
            markeredgecolor="#222222", zorder=4)

    span = radii[-1] * 1.08
    ax.set_xlim(-span, span)
    ax.set_ylim(-span, span)
    ax.set_aspect("equal")
    ax.axis("off")
    ax.set_title(title, fontsize=13, pad=14)

    dropped = total_macs - sum(counts)
    ax.text(0, -span * 0.99,
            f"{sum(counts)} devices placed \u00b7 {total_rows:,} client frames"
            + (f" \u00b7 {dropped} beyond {bands[-1]:g} m not shown" if dropped else ""),
            ha="center", va="bottom", fontsize=8, color="#777777")
    ax.text(0, span * 0.99,
            "Rings are distance only \u2014 bearing is not measured",
            ha="center", va="top", fontsize=8, color="#777777", style="italic")

    fig.colorbar(ScalarMappable(norm=norm, cmap=cmap), cax=cax,
                 label="distinct devices in ring")
    fig.tight_layout()
    fig.savefig(out_path, dpi=150, facecolor="white")
    print(f"Wrote {out_path}")


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("pattern", help="glob for night_sniffer CSV files, quoted")
    p.add_argument("--bands", default=",".join(str(b) for b in DEFAULT_BANDS),
                   help="comma-separated ring OUTER edges in metres "
                        f"(default: {','.join(str(b) for b in DEFAULT_BANDS)})")
    p.add_argument("--since", default=None,
                   help="only rows with Timestamp_ISO >= this, e.g. "
                        "2026-09-09T08:00")
    p.add_argument("--scale", choices=["equal", "true"], default="equal",
                   help="ring widths: 'equal' gives every band the same width "
                        "(default, keeps colour readable); 'true' draws radius "
                        "to metric scale.")
    p.add_argument("--out", default="ring_density.png")
    p.add_argument("--title", default="Device density by distance")
    args = p.parse_args()

    bands = sorted(float(b) for b in args.bands.split(",") if b.strip())
    if not bands:
        sys.exit("--bands needs at least one value")

    labels, counts, total_macs, total_rows = load_counts(
        args.pattern, bands, args.since)
    if not total_rows:
        sys.exit("No client frames with a usable distance matched the filters.")

    for label, n in zip(labels, counts):
        print(f"  {label:>12}  {n}")
    render(labels, counts, bands, args.out, args.title, total_macs, total_rows,
           scale=args.scale)


if __name__ == "__main__":
    main()