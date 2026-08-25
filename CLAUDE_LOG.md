# Claude Log

## Main Objective

Track changes Claude makes to the Wi-Fi Sniffer project, in the same style as `TASK_LOG.md`. but always record a time of writing in 24-hour format also.

## 2026-07-14 Print all frame types in real-time terminal log

- Changed `handle_packet()` in `src/night_sniffer_v3.py` so every tracked frame type is printed to the live terminal, not only client frames.
- Previously the terminal print was gated on `if pkt_type in CLIENT_FRAME_TYPES`, so beacons (and any AP-side frame) were written to `wifi_full_recon_report.csv` but never shown live. This is why beacons "could not be detected" in the console even with APs nearby.
- New behavior:
  - Removed the `CLIENT_FRAME_TYPES` gate around the `print(...)` call so it always runs for any frame `classify_frame()` recognizes.
  - Added a `frame_tag` prefix so the line still shows what kind of frame it is:
    - `[C]` for client frames (`PROBE`, `ASSOC_REQ`, `REASSOC_REQ`, `AUTH`, `DEAUTH`, `DISASSOC`).
    - `[A]` for AP/other management frames (`BEACON` today, plus anything new).
  - This is future-proof: any new frame type added to `classify_frame()` later will print automatically without touching this block again.
- Kept the CSV logging unchanged. Frames were already written to the CSV for all types; only the terminal visibility changed.
- Related finding (not caused by this session): beacons often appear missing because channel hopping is opt-in. Commit `29fb075` made hopping require the `--hop` flag (default off), so without `--hop` the radio stays on one channel and misses APs beaconing on other channels. Run `sudo python3 src/night_sniffer_v3.py --hop` to sweep channels 1-13.
- Verification run:
  - `python3 -m py_compile src/night_sniffer_v3.py` passed.
  - `python3 -m unittest tests.claude_night_sniffer_v3` passed (73 tests).
- Next possible step: if the `[A]` beacon lines are too noisy in busy areas, consider a `--quiet-ap` flag or rate-limiting AP prints, so client activity stays readable.

## 2026-07-14 Add --frames flag to choose which frames the terminal shows

- Followed up on the "next possible step" above: added a CLI flag so beacons can be hidden from the real-time terminal without touching CSV output.
- Added `--frames {all,no-beacon}` to `main()` in `src/night_sniffer_v3.py` (default `all`):
  - `all` — print every tracked frame type (unchanged default behavior).
  - `no-beacon` — print every frame except `BEACON`.
- How it is wired:
  - New module-level global `TERMINAL_FRAME_FILTER = "all"` (near `CLIENT_FRAME_TYPES`). `main()` sets it from `args.frames` via `global TERMINAL_FRAME_FILTER` before capture starts. A global is needed because `handle_packet` is the `sniff()` `prn` callback and cannot take extra arguments.
  - In `handle_packet()` the terminal print is now gated on `show_in_terminal = TERMINAL_FRAME_FILTER == "all" or pkt_type != "BEACON"`. Only the `print(...)` is gated; `_append_csv_row(...)` and `dump_ie_details(...)` still run for every frame.
  - Added a startup log line `Terminal frame filter : <mode>` so the active mode is visible when the tool launches.
- This only affects the terminal real-time log. `wifi_full_recon_report.csv` and `ie_details_report.csv` still receive all frame types, including beacons.
- Usage examples:
  - `sudo python3 src/night_sniffer_v3.py` → shows all frames (default).
  - `sudo python3 src/night_sniffer_v3.py --frames no-beacon` → hides beacons from the terminal only.
  - Combine with hopping: `sudo python3 src/night_sniffer_v3.py --hop --frames no-beacon`.
- Verification run:
  - `python3 -m py_compile src/night_sniffer_v3.py` passed.
  - `python3 -m unittest tests.claude_night_sniffer_v3` passed (77 tests).
  - Manual gating check confirmed: with `all`, BEACON and PROBE both print; with `no-beacon`, BEACON is hidden while PROBE still prints.
- Design note: chose `no-beacon` over a generic per-type filter because the request was specifically all-vs-no-beacon. If more granularity is wanted later, `--frames` could grow to accept a comma-separated allow/deny list without breaking the current two choices.

## 2026-07-14 (written 17:26) Phase 1 — frame-body dispatcher (`parse_frame_body`)

- Implemented Phase 1 from `prompts/phase1_framebody.prompt.md` against `src/night_sniffer_v3.py`. Full handoff detail is in `explanation/20260714_1726_framebody.md`; this is the summary.
- Precondition check: read `explanation/20260714_1120_backbone.md` to confirm Phase 0 (seq → `Seq_Num` column, tag-0-only SSID, `00:50:f2` type-byte fix). Phase 1 builds on that and does not re-extract the sequence number.
- Added to `src/night_sniffer_v3.py`:
  - `parse_frame_body(pkt, pkt_type)` — dispatcher returning subtype fixed fields (listen interval, capability info, current AP, security tier, auth status, reason code, direction); malformed frames are swallowed so the `sniff()` callback never dies.
  - Two pure, unit-tested helpers: `auth_tier(algo, tags)` and `frame_direction(pkt)`.
  - Seven CSV columns appended **after `Seq_Num`** (never inserted): `Listen_Interval, Cap_Info, Current_AP, Security_Tier, Auth_Status, Reason_Code, Direction`. `CSV_FIELDS` is now 25 wide.
  - Store-only `Session` fields `current_aps` / `listen_intervals` / `security_tiers`, filled via `track_session()`→`_update_session()` (new optional args, defaulted). **Not** used in any scoring/merge/veto — that is Phase 2.
  - Wired `parse_frame_body` into `handle_packet()` after `extract_ie_details`.
- Scope kept: no active/transmit techniques; no Phase 2 scoring; no HT/VHT byte parsing (Phase 3); no WPS/taxonomy (Phase 4); Assoc/Reassoc RESPONSE Status/AID deliberately deferred (flagged for senior sync).
- CSV operational note: appended-at-end means pre-Phase-1 rows are narrower than new rows. On a deployed sniffer with an existing report, rotate/rename it once before the first Phase 1 run so `setup_csv()` writes a fresh 25-column header. No live report exists in this tree, so nothing was rotated.
- Verification:
  - `python3 -m py_compile src/night_sniffer_v3.py` and `python3 -m compileall -q src tests` passed.
  - `PYTHONPATH=src python3 -m unittest discover -s tests -p '*.py'` passed — 96 tests.
  - Helper unit tests added for `auth_tier` (5 cases) and `frame_direction` (4 cases).
  - Updated two Phase 0 tests that assumed `Seq_Num` was the last column (now reference index `-8`); this is a test-expectation fix, not a behavior regression.
  - No linter configured (no ruff/flake8/pyproject/setup.cfg; CI has no lint step), so none was run.
  - Functional drive confirmed ASSOC_REQ/REASSOC_REQ fields populate and land in the store-only Session sets.
- Did not run any git command (prompt: human manages version control). Edited files left in the working tree for review.

## 2026-07-16 (written 11:35) Wrote Phase 0 + Phase 1 explanation (presentation)

- Created `explanation/20260716_1135_phase0_phase1_summary.md` — a documentation-only, presentation-oriented explanation. No source code was changed.
- Checked `git log` to pin the two phases: Phase 0 = `98029c1` "AI is the power"; Phase 1 = `92185c9` "Implemented phase 1". Read both diffs with `git show`.
- Covered, per the request:
  - Baseline capability that existed before both phases (capture loop, `classify_frame`, raw-TLV IE extraction, fingerprinting, distance, session tracking, reporting).
  - Phase 0: added `Seq_Num` capture from `Dot11.SC`, tag-0-only SSID fix, `00:50:f2` WMM/WPS type-byte fix + `NON_DEVICE_VENDOR_IE_OUIS`, and the unused-for-now `seq_delta()` helper.
  - Phase 1: `parse_frame_body()` dispatcher, `auth_tier()`/`frame_direction()` helpers, 7 appended CSV columns, and store-only `Session` fields.
  - Frame types captured: 9 (BEACON, PROBE, ASSOC_RESP/REQ, REASSOC_RESP/REQ, AUTH, DEAUTH, DISASSOC).
  - IEs: 26 named in `IE_NAMES`, subset decoded in `_decode_ie`, fingerprint built in `extract_ie_details`.
  - Inferred device info: vendor, real vs randomized MAC, device class/region, distance/zone, security tier, roaming, OS/driver hints, lifecycle events, presence/dwell.
- Grounded entirely in the current `src/night_sniffer_v3.py` and git history; no active/transmit or scope-widening content introduced.

## 2026-08-03 (written 10:21) Band selection (2.4/5/both), camp-vs-hop mode, and `--iface`

- Driven by a new dual-band 5 GHz adapter. Five design points were confirmed with the human before any code was written: flags-win-then-prompt input style, an interface option, one dual-band adapter (not two), startup channel probing for 5 GHz, and "both bands" as a third band choice.
- New config block in `src/night_sniffer_v3.py` (after `CHANNEL_HOP_INTERVAL`), all editable in code:
  - `DEFAULT_CAPTURE_MODE = "hop"`, `DEFAULT_BAND = "2.4"`, `DEFAULT_CAMP_CHANNEL = 6`.
  - `CHANNELS_2GHZ` (1–13; 14 is Japan-only and excluded) and `CHANNELS_5GHZ` (full 25-channel regulatory set, UNII-1 through UNII-3, DFS channels annotated).
  - `PROBE_HOP_CHANNELS = True` / `PROBE_SETTLE = 0.05`.
  - `INTERFACE` keeps its value but is now the *default*, not the only option.
- New "Channel control" section (placed after interface recovery):
  - `set_channel(iface, channel, quiet=False)` — extracted from the old inlined `subprocess.run` in `channel_hopper`; returns success so callers can react. Retuning is receive-side only, so this stays passive.
  - `_channel_band_label(channel)` — resolves a channel to "2.4GHz"/"5GHz"/"unknown" against the configured lists.
  - `build_hop_channels(band)` — "both" is a single concatenated rotation walked by the one existing hopper thread, not two threads and not an interleave. Returns a copy so callers cannot mutate the config lists.
  - `probe_channels(iface, channels)` — tunes each channel once at startup and keeps only what the driver accepts. This is what makes shipping the full DFS list safe: channels 52–144 are radar-shared and marked RADAR/NO-IR, and some driver + regdomain combinations refuse them even though we only ever listen. Refusals are dropped once instead of burning a `CHANNEL_HOP_INTERVAL` dwell on every sweep forever. If *nothing* is tunable (interface not in monitor mode) it logs the fix and hands back the unverified list rather than an empty rotation.
- `channel_hopper()` now takes `(iface, channels)` instead of reading globals and hardcoding `range(1, 14)`.
- New "Startup prompts" section — `_stdin_is_interactive`, `_ask`, `prompt_choice`, `prompt_interface`, `prompt_capture_mode`, `prompt_band`, `prompt_camp_channel`. Prompt order is interface → mode → (band | channel), so the camp-vs-hop question sits above the band question as requested. Bare Enter takes the default, menu number or key name both accepted, invalid answers re-ask, `EOFError` falls back to the default and Ctrl+C exits cleanly.
- `main()` resolution order per setting: **CLI flag wins → prompt if stdin is a TTY → `DEFAULT_*` constant.** Non-TTY runs (nohup/cron) log that prompts are skipped and never block on `input()`.
- New flags `--iface`, `--mode {camp,hop}`, `--band {2.4,5,both}`, `--channel N`. `--hop` is kept as a backwards-compatible alias for `--mode hop`; `--hop` together with `--mode camp` is rejected by `parser.error`. `--band` in camp mode and `--channel` in hop mode log an "ignored" warning.
- Camp mode failure handling: if the driver refuses the requested channel, the run exits 1 with the monitor-mode command spelled out. Capturing silently on the wrong channel is worse than stopping.
- Interface recovery now goes through a new `recover_interface()` closure in `main()`: a monitor-mode reset drops the radio to the driver's default channel, so a camped channel has to be re-applied afterwards. Hop mode self-heals because the hopper re-issues its channel every dwell.
- **Behaviour change to be aware of:** previously a bare run did not hop at all and `--hop` opted in. Now a bare run prompts (TTY) or falls back to `DEFAULT_CAPTURE_MODE = "hop"` (non-TTY). There is no longer a "leave the channel exactly as-is" mode — see the note below.
- Verification:
  - `python3 -m compileall -q src tests` passed.
  - `PYTHONPATH=src python3 -m unittest discover -s tests -p '*.py'` passed — 126 tests (96 existing, all still green, plus 30 new).
  - New test classes in `tests/claude_night_sniffer_v3.py`: `SetChannelTests`, `ChannelBandLabelTests`, `BuildHopChannelsTests`, `ProbeChannelsTests`, `ChannelHopperTests`, `StdinInteractiveTests`, `PromptChoiceTests`, `PromptCampChannelTests`, `PromptDefaultsTests`.
  - Drove `main()` end-to-end with scapy and `iw` stubbed across 12 scenarios (each band, camp, legacy `--hop`, refused-channel exit, contradictory flags, piped interactive answers, invalid-input re-asks). A fake driver refusing 120/124/128/165 confirmed the probe filters exactly those and the sweep shrank from 25 to 21 channels.
  - No linter configured (no ruff/flake8/pyproject/setup.cfg; CI has no lint step), so none was run.
- Scope kept: passive only — no transmission was added; `iw set channel` is receive-side tuning. No payload capture, no export paths, no changes to CSV columns or session logic.
- Did not run any git command that writes; human manages version control.

## 2026-08-03 (written 10:30) Wrote up the band-selection suggestions

- Created `explanation/20260803_1030_suggestion.md` — documentation only, no source code changed.
- Captures the five "Suggestions / Issues noticed" items raised alongside the band-selection change above, each with file:line grounding, why it matters, and what the fix would look like: stale `CLAUDE.md:33-34` Commands section, the loss of a "leave the channel as-is" mode, the missing 6 GHz branch in `_freq_to_channel()`, CWD-relative output paths versus the `__file__`-anchored convention, and uniform dwell time hurting probe-request capture on the longer "both" sweep.
- Also records two non-issues for future reference: why shipping the full DFS list is only safe while `PROBE_HOP_CHANNELS` is on (and what to trim if it is ever turned off), and confirmation that `iw set channel` is receive-side only so the passive constraint is intact.
- None of the five were fixed — each is either out of scope for the task that was asked, or a decision for the human.

## 2026-08-04 (written 16:10) Documented every flag, prompt, and default

- Created `explanation/20260804_1610_flags_and_options.md` — documentation only, no source code changed.
- Full inventory of `src/night_sniffer_v3.py` startup surface: six CLI flags (`--iface`, `--mode`, `--band`, `--channel`, `--hop`, `--frames`) plus argparse's `-h/--help`, and the four interactive prompts (interface, capture mode, band, camp channel).
- Leads with the resolution rule that explains the whole design — **CLI flag → prompt if stdin is a TTY → `DEFAULT_*` constant**, applied per setting independently — and records that `--frames` is the sole exception, having a real argparse default (`"all"`) and therefore no prompt and no `DEFAULT_*` constant.
- Per flag: argparse default vs effective default, choices, whether it prompts, mode applicability, and validation. Records the three interaction rules: `--hop` with `--mode camp` is a `parser.error`, `--band` is ignored in camp mode, `--channel` is ignored in hop mode.
- Per prompt: literal on-screen text, the default shown in brackets, accepted answers (key or 1-based menu number, lowercased), and the shared `_ask` behaviour — bare Enter takes the default, `EOFError` falls back, Ctrl+C raises `SystemExit("Cancelled at startup prompt.")`. Only `prompt_camp_channel()` validates; the flag path for `--channel` does not, which is noted.
- Tabulates band expansion (2.4 → 13 ch / 6.5 s, 5 → 25 ch / 12.5 s, both → 38 ch / 19.0 s at the current `CHANNEL_HOP_INTERVAL`), flagged as pre-probe figures since `PROBE_HOP_CHANNELS` trims refusals at startup.
- Also lists the code-only config with current values and line numbers (output paths, `P0`/`N`, session/grouping thresholds, channel plan, probe settings, retry settings), an exit-status table (0 / 1 / 2 / prompt-cancel), and seven worked command examples.
- Every value transcribed from the source at commit `51f1166`; the script was not executed (importing it triggers a `MacLookup` metadata download), so all figures are derived from the code rather than observed output.
- Did not run any git command that writes; human manages version control.

## 2026-08-07 (written) Researched vendor identification from radio/IE specification data

- Created `research/2026-08-07_vendor_id_from_wifi_specs.md` and `research/vendor_ie_reference.md` — research/documentation only, **no source code changed**.
- Question researched: how to attribute a device vendor when the MAC is randomized *and* the IE set is too sparse for the existing tag-221 OUI path (`vendor_from_ie_ouis()`, `src/night_sniffer_v3.py:333`) to resolve anything.
- Main note surveys signals in six tiers, ranked by value-per-effort: vendor IE **OUI+type byte**, WPS/WSC vendor strings, randomized-MAC structural patterns, radio capability *field values* (HT/VHT/HE), supporting IEs (127/59/33/36/70/107/1/50), and behavioural signals (sequence numbers, IE ordering, probe timing).
- Key finding, grounded in the 2024 APB paper's discriminator ranking: vendor-specific tags (7 of top-16 filters), HT Capabilities (6), Extended Capabilities (3). Our code keeps only 3 of the 4 vendor-type bytes, treats HT as a presence boolean, and never reads tag 127.
- Highest-leverage recommendation recorded: build a local signature table seeded from our own captures — every *global*-MAC frame is a free labelled pair (real OUI vendor ↔ radio signature), which can then label randomized frames. Caveat also recorded: many Android devices emit a reduced signature when randomizing, so match on the stable radio subset rather than the full IE sequence.
- Reference file carries paste-ready lookup data: 4-byte vendor-type table (confirmed from hostapd `ieee802_11_defs.h`), WPS/WSC attribute IDs, Primary Device Type categories, randomization-prefix table, and full bit layouts for HT Capability Info, A-MPDU Parameters, VHT Capabilities Info, and the tag-255 extension IDs. Items not verified from a primary source are marked *verify*.
- **Ethical items raised for human decision, not implemented:**
  - WPS `0x1047` UUID-E is reversible to the device's real global MAC via precomputed tables (~100% success in the literature). Passive, so not a rule violation, but it converts our output from session identifiers into permanent hardware identifiers. Recommended **against** implementing.
  - WPS `0x1011` Device Name is frequently a personal name. Recommended not to log, or to log presence only.
  - Recorded that the RTS/CTS derandomization technique from the literature requires frame transmission and is therefore **prohibited** by the passive-capture rule — noted explicitly so it is not rediscovered and mistaken for an option.
- No dependencies added, no tests run (no code changed), no git write commands run.

### Suggestions / Issues noticed
1. `src/night_sniffer_v3.py:565` — tag 255 is flagged as `EXT_CAP`, but 255 is *Element ID Extension*; Extended Capabilities is tag 127. `IE_NAMES` (`:144`, `:149`) is correct, the capability-flag logic is not. Effect: 11ax/11be devices mislabelled, tag 127 never flagged.
2. `src/night_sniffer_v3.py:192` — `NON_DEVICE_VENDOR_IE_OUIS` omits `50:6f:9a` (Wi-Fi Alliance: P2P/WFD/HS2.0/MBO), so a common protocol IE can be reported as a device vendor. Live false positive.
3. `src/night_sniffer_v3.py:555` — SSID (tag 0) is folded into the IE fingerprint, so directed probes for different SSIDs from one device yield different `ie_fingerprint` hashes, weakening the session linking the hash exists for. Consider excluding tag 0 and tag 3.
4. `src/night_sniffer_v3.py:555` — `info[:8]` truncation on the 26-byte HT Capabilities element discards most of the MCS set and all beamforming capability bytes before hashing.
5. `src/night_sniffer_v3.py:166` — `KNOWN_OUIS` is queried from two different namespaces (MAC OUI prefixes at `:658`, tag-221 vendor OUIs at `:351`). Conflating them is why the `00:50:f2` entry has to read "Microsoft (Surface/WPS)". Worth splitting into two tables.

## 2026-08-07 (written 11:40) Wrote up the IE-parsing / vendor-attribution suggestions

- Created `explanation/20260807_reverse_engineer_suggestion.md` — documentation only, **no source code changed**.
- Expands the five "Suggestions / Issues noticed" items raised alongside the vendor-identification research above, following the format of `explanation/20260803_1030_suggestion.md`: summary table, then one section per issue with what the code does, why it is wrong, a worked failure case, verified blast radius, and options with trade-offs.
- **Re-ordered by verified impact** rather than discovery order. Traced every consumer before writing: only two of the five can change a device count.
  1. SSID (tag 0) folded into the IE fingerprint (`:555`) — **inflates** the people count. Worked the arithmetic: a fingerprint miss costs −3 against `GROUP_SCORE_THRESHOLD = 6`, dropping the ceiling from 12 to 6, so a correct merge then needs all six remaining signals to land. Tag 3 (DS Parameter Set) is worse in `--mode hop` because it varies by design of our own sweep.
  2. `info[:8]` truncation (`:555`) — **deflates** the count. Tabulated what survives per element; the worst case is HE Capabilities, where 1 of the 11 chipset-rich HE PHY bytes is kept. Recorded that this must be fixed *after* #1, never before, or it amplifies the over-splitting.
  3. `50:6f:9a` missing from `NON_DEVICE_VENDOR_IE_OUIS` (`:192`) — traced the full path showing a randomized Android emitting a P2P IE resolves to "Wi-Fi Alliance" via the `_vendor_lookup` fallback at `:356`.
  4. Tag 255 flagged `EXT_CAP` (`:565`) — 255 is Element ID Extension, 127 is Extended Capabilities. `IE_NAMES` (`:144`, `:149`) is already correct, so the two CSV files currently disagree about the same frame.
  5. `KNOWN_OUIS` (`:166`) queried from both the MAC-prefix and vendor-IE namespaces.
- Two findings added that were not in the original list, both in `get_correlation_identity()`: (a) `Vendor` uses the full `mac_vendor_lookup` DB while `Note` uses only the 21-entry `KNOWN_OUIS`, so adjacent CSV columns can disagree on the same MAC; (b) the `:701` fallback is unreachable because `vendor` is overwritten at `:658` by a function that never returns `"Generic"`.
- Recorded two blast-radius facts that are easy to assume wrongly: `estimate_devices_from_csv.py` hard-exits on v3 output (it requires the lowercase `wifi_sniffer.py` schema per `estimate_devices_from_csv.py:116-121`), and `identity` never reaches the merge scoring — it is stored at `:1019` and printed at `:1058` only.
- Nothing was fixed. Every item is either outside the scope of the research task or a decision for the human. Suggested work order and a note that #1 and #2 both invalidate historical `IE_Fingerprint` values and should ship as one migration if both are taken.
- No dependencies added, no tests run (no code changed), no git write commands run.

## 2026-08-13 (written 13:22) Fixed tag 127 / tag 255 capability flags (change set B)

- Implemented **change set B only** of `prompts/20260813-1257-ie-fingerprint-fix-plan.md` (issue 4). Change set A (issues 1 + 2 + fingerprint versioning) is deliberately **not** in this change — it is gated on the Step 0 baseline measurement, which is Pla2's to run.
- One edit, inside the capability-flag chain of `extract_ie_details()` (`src/night_sniffer_v3.py:563-566` pre-edit): split the single `elif ie_id == 255: capability_flags.add("EXT_CAP")` into a tag-127 branch and a tag-255 container decode.
  - Tag 127 (Extended Capabilities) was never checked at all, so a high-ranked discriminator never reached the `Capabilities` column.
  - Tag 255 is Element ID Extension — a *container* whose first payload byte selects the element. Now maps ext ID 35/36 → `HE`, 108 → `EHT`, anything else → `EXT{n}`. A Wi-Fi 6 and a Wi-Fi 7 device previously produced the identical flag.
  - `IE_NAMES` (`:144`, `:149`) already had both tags right, so `ie_details_report.csv` and `wifi_full_recon_report.csv` had been disagreeing about the same frame. They now agree.
- Three points recorded in the explanation because they are load-bearing and not obvious from the result: the `and info` guard prevents `IndexError` inside the Scapy callback on a zero-length tag 255 reachable from a truncated frame; `EXT{n}` keeps unrecognised extensions as discovery data (free — `capabilities` is not an input to `_same_randomized_session_score()`); the `for ie_id, info in _iter_ies(pkt)` loop was left untouched so repeated tag 255 in one frame still yields both flags.
- **No schema change** — `CSV_FIELDS` stays at 25 columns; `Capabilities` was already a semicolon-joined variable-membership set. **Cannot move a device count** — `capabilities` reaches the CSV (`:1220`) and nothing else, which is why this ships ahead of change set A with no migration note and no `FINGERPRINT_VERSION` bump.
- Verified: `compileall` clean; `unittest discover` 126 tests pass. All branches exercised directly against `extract_ie_details()` with hand-built TLV bytes — tag 127 → `EXT_CAP`; ext 35/36 → `HE`; ext 108 → `EHT`; ext 9 → `EXT9`; zero-length tag 255 → empty, no exception; ext 35 + ext 108 in one frame → `EHT;HE`.
- Explanation written to `explanation/20260813-1322-ie-capability-flags-tag127-tag255.md`. No dependencies added, no git write commands run.

### Suggestions / Issues noticed
1. `tests/test_night_sniffer_v3.py:153` — the only IE test asserts `ie_sequence` and `vendor_ies` only, so nothing in the fingerprint or capability path has test coverage. The plan's *Validation* section assumes a golden fixture corpus that does not exist in the repo; `pcap_files/` and `csv_analyze/` hold only `.gitkeep`. Change set A rewrites every `IE_Fingerprint` value with no automated oracle to catch a regression.
2. `prompts/20260813-1257-ie-fingerprint-fix-plan.md:7` cites its source as `research/20260807_reverse_engineer_suggestion.md`; the file is actually at `explanation/20260807_reverse_engineer_suggestion.md`.
3. Pre-existing, untouched, reported by Pylance after the renumbering: `device_class` is assigned and never read at `src/night_sniffer_v3.py:665` and `:709`, and `_label` is unused at `:1325`. All three sit in `get_correlation_identity()` and the reporting path, which the plan places out of scope.
4. Ext ID 108 → `EHT` is still marked *verify* in `research/vendor_ie_reference.md`. It is implemented as the plan specifies, but has not been confirmed against a primary source or a real Wi-Fi 7 capture.

## 2026-08-13 (written 13:40) Baseline measurement script, plan-source fix, pruned dead `device_class`

Three follow-ups from the change set B review. No change to capture behaviour.

- **Added `scripts/fingerprint_baseline.py`** — standard library only, no new dependencies. Answers Step 0 of `prompts/20260813-1257-ie-fingerprint-fix-plan.md` without any CSV leaving the Pi: it reads the capture files in place and prints **aggregate counts only** — never a MAC, SSID, fingerprint value, or raw IE hex. Reports the two acceptance metrics (distinct fingerprints per MAC, distinct MACs per fingerprint) as median/p95/max/mean, the distinct tag-0 and tag-3 values per MAC that size issue 1, the count and byte volume that `info[:8]` discards per tag for issue 2, the empty-fingerprint row count, and `User_N` totals per daily summary. Fingerprints-per-MAC is additionally split randomized vs global, since only the randomized population reaches the merge scorer. Paths are `__file__`-anchored with a `--csv-dir` override; `--label` tags a run pre-/post-fix. Smoke-tested against synthetic fixtures in scratchpad — the repo's own `csv_analyze/` is empty on this dev box.
- **Fixed `prompts/20260813-1257-ie-fingerprint-fix-plan.md:7`** — source cited as `research/…`, corrected to `explanation/20260807_reverse_engineer_suggestion.md`. Confirmed by Pla2.
- **Pruned dead `device_class`** from `get_correlation_identity()` (was `:665` and `:709`), on explicit human authorisation — this function is otherwise fenced off by the plan under deferred issue 5, and nothing else in it was touched. Confirmed dead before deleting: two writes, zero reads, and none of the four return paths reference it. The `if len(ch_list) > 11:` guard went with it, since removing only its body leaves an empty block. Alignment of the surrounding assignments was deliberately left as-is rather than re-padded, to avoid reformatting untouched lines.
- `compileall` clean; `unittest discover` 126 tests pass after both edits.

### Suggestions / Issues noticed
1. **`get_correlation_identity()` reads tag 50 as a channel list, but tag 50 is Extended Supported Rates.** At `:705` it does `ch_list = list(tag50.info)` and infers `region = "TH/EU" if (12 in ch_list or 13 in ch_list)`. This file's own tables disagree with that reading: `IE_NAMES:136` labels tag 50 "Extended Supported Rates" and `_decode_ie:613` decodes it as rates in 0.5 Mbps units. Rate byte 12 is 6 Mbps and 13 is 6.5 Mbps — 6 Mbps is a near-universal OFDM rate, so the TH/EU branch likely fires for most devices regardless of region. Tag **36** is "Supported Channels" (`IE_NAMES:132`) and would make `ch_list`, the 12/13 test, and the deleted `len(ch_list) > 11` check all coherent, so a `36`→`50` transposition is the likely origin. Not fixed — `region` is live code feeding the `Note` column and the terminal line, and the plan fences this function. Worth confirming against a capture before changing. It does **not** affect device counts (`identity` never reaches the merge scorer).
2. The same misreading is why deleting `device_class` was the right call rather than wiring it up: `len(ch_list) > 11` → "High-End" was counting supported *rates*, not channels, so completing the feature as written would have shipped the same defect into a new column.
3. `_label` at `src/night_sniffer_v3.py:1322` is a **false positive, not prunable**. `for index, (key, _label) in enumerate(options, start=1)` unpacks a 2-tuple; both slots must be bound. The `_` prefix is already the conventional discard marker, and the only alternatives are renaming it `_` or replacing unpacking with indexing — neither is an improvement. Left alone; Pylance will keep reporting it.
4. **Plan line anchors below `:566` have shifted by +15** after change set B. For change set A: A.3's sha1 block is now at `:588-592` (plan says `:573-577`), and `_same_randomized_session_score()` is at `:827` (plan says `:812`). A.1 (insert after `IE_NAMES`, `:150`) and A.2 (`:553-555`) are above the edit and unmoved. Re-verify before applying rather than trusting the plan's numbers.

## 2026-08-13 (written 14:55) Fingerprint v2 — excluded volatile tags, removed truncation (change set A)

- Implemented **change set A** of `prompts/20260813-1257-ie-fingerprint-fix-plan.md` (issues 1 + 2 + versioning), unblocked by Pla2's Step 0 baseline in `explanation/before-fix.md`. Change set B shipped separately at `279c57d` and is untouched. Three edits, all in `src/night_sniffer_v3.py`:
  - `:161`, `:172` — new module-level `FINGERPRINT_VERSION = 2` and `VOLATILE_IE_IDS = frozenset({0, 3})`, inserted after `IE_NAMES` before the Logging banner. The version comment states the bump rule as *the input to the SHA-1*, not the output schema — which is why change set B correctly did not bump it.
  - `:577-578` — `fingerprint_parts.append` is now guarded by `if ie_id not in VOLATILE_IE_IDS`, and `info[:8].hex()` became `info.hex()`. `sequence.append` stays **outside** the guard: presence and order of tags 0 and 3 are real signal, only their content is volatile, so `ie_sequence` still records them.
  - `:613-617` — emitted value is version-prefixed, `fp2:d5148b9c934e896b`, 20 chars where it was 16.
- **Plan line anchors for A.3 were stale by +16** after change set B (plan says `:573-577`, actual `:589-593` pre-edit). Re-verified all three anchors against the file rather than trusting the plan, per the note left in the previous log entry.
- The `if raw_fingerprint else ""` arm at `:616` was kept structurally intact — the highest-risk line in the change. A prefix-then-append rewrite would make IE-less frames emit a truthy `"fp2:"`, a fingerprint shared by every such frame, scoring **+3** at `:863` on merges backed by no evidence. Verified: both the no-IE frame and the volatile-tags-only frame yield `''`.
- **No schema change** — `CSV_FIELDS` stays at 25 columns. Confirmed nothing downstream parses the format: the two `split()` calls on a "fingerprint" field (`:1008`, `:1095`) operate on `Session.fingerprint` (`:230`), the correlation-identity string, which is a different field from `Session.ie_fingerprints` (`:231`). `scripts/fingerprint_baseline.py:126` treats the value as opaque, so it reports post-fix runs unmodified.
- Verified: `compileall` clean; `unittest discover` 126 tests pass. No golden fixtures regenerated — the plan's *Validation* section assumes a corpus that does not exist (`pcap_files/` and `csv_analyze/` hold only `.gitkeep`, and no test asserts a fingerprint value); per Pla2's instruction, nothing to regenerate means move on. All branches exercised against hand-built TLV bytes: three different SSIDs → one identical hash; ch 1 and ch 11 → one identical hash; HT caps differing only at byte 25 → two different hashes (was one); tags 0+3 only → `''`; mid-frame tag 0 excluded while `ie_sequence` stays `1,0,45`. Change set B re-checked and unaffected.
- Pla2 is validating live on the Pi against a **fresh** `wifi_full_recon_report.csv`, which satisfies the deploy precondition — `setup_csv()` (`:250`) only writes a header when the file is absent, so an accumulating file would hold v1 rows above v2 rows with no boundary.
- Explanation written to `explanation/20260813-1455-fingerprint-v2-volatile-tags-and-truncation.md`. No dependencies added, no git write commands run.

### Suggestions / Issues noticed
1. **The plan's acceptance gate cannot be satisfied as written.** It requires median *and* p95 of both metrics to fall, but `before-fix.md` shows most are already at the floor: issue 2 is median=1 **and** p95=1 (neither can decrease), and issue 1's median is 1 for both the all-MAC and randomized populations. The genuinely movable numbers are issue 1 randomized p95 (6) and mean (2.19), and issue 2's `shared by >1 MAC` (458), `shared by >5` (56) and mean (1.19). A median that stays at 1 is not a failure. Recommend restating the gate on those figures before the post-fix comparison is read.
2. **The plan's failure diagnosis does not follow from a joint measurement.** It says a worsened metric means one of the two edits is wrong. But individually the edits push opposite ways — excluding `{0,3}` removes entropy and therefore *increases* cross-MAC collisions, while removing the truncation adds entropy and *decreases* them; only the combined effect was predicted to improve both. Measuring both edits together cannot attribute a regression to either. On a single-site corpus, read direction as advisory.
3. **`max=8120` fingerprints on one MAC is a global MAC, and neither edit addresses it.** That is an AP whose beacons carry a per-beacon TIM (tag 5), which is volatile in exactly the way tags 0 and 3 are but is not in `VOLATILE_IE_IDS`. Expect the "all MACs" aggregates to stay dominated by it and barely move; the randomized split is the one that reaches the merge scorer. If beacon rows are ever wanted in the fingerprint metrics, tag 5 is the next candidate for exclusion — not proposed as a change, just recorded.
4. Verified side effect worth knowing before reading the CSV: a `tag 0 + rates` frame and a `tag 3 + rates` frame now hash identically, since after exclusion both reduce to the same rates element. `ie_sequence` still distinguishes them (`0,1` vs `3,1`) but the hash does not. Expected cost of option A, and what the truncation removal exists to offset.
5. The fingerprint path still has **no automated oracle**. Issue 1 from the previous entry stands unresolved: change set A rewrote every `IE_Fingerprint` value with only hand-verification behind it. A small unit test pinning the three invariants (volatile tags excluded, full content hashed, empty stays empty) would be cheap; deliberately not added here since the plan did not ask for one.

## 2026-08-13 (written 15:40) Handoff report on change sets A + B for the plan author

- Wrote `explanation/20260813-1540-handoff-set-a-set-b-implementation-report.md` at Pla2's request, addressed to the author of `prompts/20260813-1257-ie-fingerprint-fix-plan.md`. **Documentation only — no source code changed.**
- Covers: status of both change sets, what was implemented, six deviations from the plan with reasons, five points where the plan is factually wrong, five findings made during implementation that the plan could not have anticipated, what is left, ranked suggestions, and a scope-fence section for the next Claude Code session.
- **Deviations recorded:** stale line anchors (the plan's own commit sequence guarantees change set A's anchors are wrong by the time they are used); the pcap-replay validation method is not runnable because the tool has no offline read path (`sniff(iface=...)` at `:1568`, no `-r` flag) so Pla2 is validating live against a fresh CSV instead — before/after are now different captures, which confounds the code change with on-site variation; golden fixtures do not exist so none were regenerated; Step 0 ran only its acceptance-metric half; the acceptance gate was not applied as written; and the `get_correlation_identity()` fence was crossed once with explicit authorisation.
- **Corrected a line anchor in my own earlier outputs:** the scorer guard is `:863`, not `:850` — fixed in both `explanation/20260813-1455-...md` and the 14:55 log entry above. Every anchor in the handoff was then re-verified by grep against the current 1604-line file rather than by arithmetic; four were wrong on first write and were fixed.
- No dependencies added, no tests run (no code changed), no git write commands run.

### Suggestions / Issues noticed
1. **`generate_session_report()` (`:1076`) opens the daily summary with mode `"w"` (`:1082`) and runs every `AUTO_SAVE_INTERVAL = 60` seconds.** The plan's *Deploy precondition* says daily summaries need no action because they are per-date — true for cross-date mixing, but a v2 run **today** overwrites `daily_summary_20260813.csv`, which holds the pre-fix baseline of 99 `User_N` rows. The count survives as text in `before-fix.md`; the file does not. Archive it first if a row-level same-date comparison is wanted.
2. **`ie_details_report.csv` is ephemeral by design.** `setup_ie_csv()` (`:279`) truncates it with mode `"w"` (`:288`) on every startup and is called unconditionally from `main()` (`:1503`); dumping is not flag-gated (`:1265`). It therefore only ever holds the most recent run, while `wifi_full_recon_report.csv` accumulates — so the two halves of Step 0 structurally cannot cover the same window. This is very likely why the defect-sizing half came back `SKIPPED`. To measure issue 1 at all, the file must be copied aside at the end of a run.
3. **All three output paths are CWD-relative** (`:39-41`, `./csv_analyze/…`), against this project's own convention in `CLAUDE.md` requiring `__file__`-anchored paths. `CLAUDE.md`'s documented run command implies a working directory of `src/`, so captures likely land in `src/csv_analyze/`, while `scripts/fingerprint_baseline.py` is correctly `__file__`-anchored and defaults to the repo-root `csv_analyze/`. **Pass `--csv-dir` explicitly on the post-fix run** or the baseline will report on the wrong directory. Not fixed — out of scope, and relocating live-capture output is not a drive-by decision.
4. **`explanation/` is gitignored (`.gitignore:38`) and `git ls-files explanation/` returns zero tracked files.** Every write-up these plans commission is untracked, including `before-fix.md` — the only record of the pre-fix baseline — and the handoff document itself. The tracked record is `CLAUDE_LOG.md`. If those write-ups are meant to be reviewable artifacts, the ignore rule needs revisiting. Not changed; `.gitignore` is Pla2's call.
5. **The baseline suggests the defects were smaller than the plan's framing implies.** For randomized MACs — the only population reaching `_same_randomized_session_score()` — the pre-fix median was already 1 (p95 6, mean 2.19, n=1207), and only 458 of 9626 fingerprints (4.8%) were shared across MACs. The extreme figures live almost entirely in the 83 global MACs (mean 106, max 8120), which never reach the scorer. Expect modest `User_N` movement; that will be consistent with the baseline rather than evidence of a failed fix.

## 2026-08-13 (written 16:45) Analysed the post-fix measurement; extended the handoff report

- Pla2 committed change set A (`8236024`) and ran the post-fix measurement (`explanation/post-fix.md`) while the handoff was being written. Extended `explanation/20260813-1540-handoff-set-a-set-b-implementation-report.md` with a new §3 covering the results. **Documentation only — no source code changed.**
- **Headline finding: the before/after comparison is not valid, and should not be presented as evidence the fix worked.** `before-fix.md` was measured over a `wifi_full_recon_report.csv` that had accumulated across ~6 sessions (2026-07-24 → 08-13), because `setup_csv()` (`:272`) only writes a header when the file is absent; `post-fix.md` was measured over a fresh file holding **one** session. Three independent checks confirm it:
  - Mean fingerprints per **global** MAC fell 106.10 → 21.18. AP beacon churn is driven by TIM (tag 5), which is 4–6 bytes — *below* the old 8-byte window, so removing the truncation cannot affect it — and tag 5 is not in `VOLATILE_IE_IDS`. Neither edit can produce a 5× drop there; only a different corpus can.
  - Empty fingerprints **fell** 0.364% → 0.122% when the plan and both write-ups predicted a rise. Post-fix the empty condition is a strict superset of pre-fix, so a lower rate is impossible on the same frame mix. Recording this explicitly: it is a prediction from my own 14:55 write-up that did not hold.
  - Rows per MAC is nearly unchanged (98.3 → 101.8) while MAC count fell 1290 → 524 — the signature of the same per-session density over fewer sessions.
- **Issue 2 worsened on every size-normalized measure**, exactly as predicted: mean MACs/fingerprint 1.19 → 1.31, p95 1 → 2, share shared by >1 MAC 4.76% → 5.96%, by >5 MACs 0.58% → 1.49%. By the plan's literal gate this is a "stop and investigate"; it is instead the expected entropy cost of excluding `{0,3}`, not an implementation error.
- **Derived why the plan's gate can never be met, beyond the floor argument.** The two acceptance metrics are two views of one bipartite (MAC, fingerprint) graph: `pairs = M × mean(fp per MAC) = F × mean(MAC per fp)` — verified to within 0.1% on both datasets. So `mean(MAC per fp) = (M/F) × mean(fp per MAC)`: reducing entropy shrinks `F` and **mechanically raises** MACs-per-fingerprint. The two cannot both fall unless the edits delete spurious (MAC, fingerprint) pairs. Recommended primary metric is mean/p95 fingerprints per **randomized** MAC, with MACs-per-fingerprint demoted to a diagnostic.
- **The defect sizing arrived this time and is internally valid** (it measures frame content, not hash behaviour; its `n=524` matches the recon MAC count, confirming both halves covered the same session). Issue 1 was small — tag 0 varied at a mean of 1.20 distinct values per MAC, and **tag 3 was emitted by only 7 of 524 MACs with zero variance**, so excluding tag 3 removed no measurable over-splitting and the plan's hop-sweep rationale is not observable here. Issue 2 was large and real — 51.1% of IEs exceeded 8 bytes and 7.52 MB of content was being discarded, led by tag 255 (2.90 MB), tag 221 (1.53 MB), tag 45 HT Capabilities (949 KB). This vindicates the plan's insistence on shipping both edits together.
- `daily_summary_20260813.csv` was overwritten by the post-fix run exactly as predicted in the 15:40 entry — pre-fix 99 survives only as text in `before-fix.md`. `User_N` 99 → 90 is not interpretable across unlike corpora.
- No dependencies added, no tests run (no code changed), no git write commands run.

### Suggestions / Issues noticed
1. **Confirm the tag-3 result before trusting it.** Only 7 of 524 MACs emitted DS Parameter Set, yet 74 global MACs (APs) were seen and APs ordinarily advertise it in every beacon. Either the capture is unusual or tag 3 is being dropped before `dump_ie_details()` (`:1265`) — which would be a parsing defect worth more than either change set. One command settles it: `tshark -r <capture>.pcap -Y wlan.fc.type_subtype==8 -T fields -e wlan.tag.number -E occurrence=a | head` (the plan's own cross-check, with the beacon subtype instead of probe requests).
2. **To get a valid comparison, cheapest first:** filter the archived pre-fix CSV to a single date and re-run `scripts/fingerprint_baseline.py` on that subset (needs a date filter, ~10 lines, and requires the pre-fix CSV to have been archived — it is not on the dev box); or capture a second post-fix session to gauge site noise; or build the pcap replay harness for a true A/B on identical input.
3. **Tag 201 appears 49,700 times as `Unknown(201)`**, losing 447 KB to truncation — more frequent than several named elements. Believed to be Reduced Neighbor Report (multi-band / 6 GHz discovery), which would make it a useful discriminator and a natural `IE_NAMES` addition. Marked *verify*, not asserted — given the tag-50 misreading already in this file, an unverified element-ID assumption is precisely the error worth not repeating.
4. Restated from the 15:40 entry because it now has evidence behind it: the plan's acceptance gate should be replaced before senior review, and the current numbers should not be presented as demonstrating the fix.

## 2026-08-18 (written 11:01) Phase 0 — offline replay path + management-frame parity harness

- Investigated where `src/night_sniffer_v3.py` prunes management frames, after a report that it captures less than `dumpcap -f 'type mgt'`. **The prune is in `classify_frame()` (`:1148`), not in any IE-level blacklist.** Verified by running scapy 2.7.0 (the pinned version) from source on the dev box, stubbing `mac_vendor_lookup`, and importing the real module to test its own functions against synthesized frames.
- **Measured coverage: 9 of 16 management subtypes reach the CSV.** `classify_frame()` is an allowlist of Scapy layer classes and `handle_packet:1185` returns immediately on `(None, "")`. Dropped whole: **5 Probe Response**, 6 Timing Advertisement, 7 reserved, **9 ATIM**, **13 Action**, **14 Action No Ack**, 15 reserved. Probe Response and Action are ordinarily the second and third most common management frames after beacons. `Dot11ProbeResp`, `Dot11Action` and `Dot11ATIM` all exist in scapy 2.7.0 (`dot11.py:1608, 1644, 1571`); they are simply absent from the import list at `:19-24`.
- **`REASSOC_RESP` is unreachable on this hardware.** `Dot11ReassoResp` subclasses `Dot11AssoResp` (`dot11.py:1600`), `Dot11FCS` sets `match_subclass = True` (`dot11.py:831`), and scapy's `haslayer` propagates `_subclass=True` down the layer chain. So whenever radiotap advertises FCS-at-end — which ath9k_htc does — `haslayer(Dot11AssoResp)` at `:1165` is True for a Reassociation Response, and it is tested *before* `Dot11ReassoResp` at `:1169`. Measured: no FCS → `REASSOC_RESP`; FCS → `ASSOC_RESP`. The docstring at `:1158-1159` claims the ordering prevents exactly this; for that one pair it is backwards. **Not fixed — that is Phase 1.**
- **The vendor / Microsoft-WPS blacklists were investigated and cleared.** None of them drop captured data: `NON_DEVICE_VENDOR_IE_OUIS` (`:214`) only feeds the `Vendor` display name via `vendor_from_ie_ouis()` (`:366`); the WMM/WPS skip in `get_correlation_identity()` (`:711-717`) only shapes the identity string; `VOLATILE_IE_IDS` (`:172`) only excludes tags from the SHA-1 input. Tags 0 and 3 still appear in `IE_Sequence` and in `ie_details_report.csv`.
- **`_iter_ies()` is sound; its anchor is not.** Diffed it against a ground-truth TLV walk of raw wire bytes across five cases — well-formed modelled elements, unknown element mid-chain, zero-length elements, RSN with unmodelled trailing bytes, odd-length Country. All pass, and `bytes(first_elt)` was byte-exact against the wire every time, so the re-serialisation concern does not materialise. The defect is `:549`: `getlayer(Dot11Elt)` returns `None` for an Action frame (scapy dissects `Dot11 / Dot11Action / Raw`), so those elements are unreachable even once the frame is classified. Phase 2 must compute the element offset from the frame rather than anchoring on a layer.
- Implemented **Phase 0** of the agreed four-phase plan — build the oracle before changing capture behaviour. Two deliverables:
  - **`--pcap FILE` offline replay** in `src/night_sniffer_v3.py`. Feeds a recorded capture through the same `handle_packet()` as a live run. Opens no interface, tunes no channel, starts neither the hopper nor the auto-save thread. New `run_replay()`, plus `REPLAY_MODE` / `_CURRENT_FRAME_TIME` globals, `_frame_time()` and `_now()`. Also `--out-dir`, which is **not optional in practice**: `setup_ie_csv()` (`:288`) opens the per-IE report with mode `"w"`, so a replay without it would truncate the IE breakdown belonging to a real capture.
  - **`scripts/mgmt_parity.py`**, which measures two things against one pcap. Frame coverage uses the frame's own type/subtype field as ground truth, so it needs only scapy; element coverage shells out to `tshark` for `wlan.tag.number` and is skipped with a clear message when tshark is absent. Both join on file position. It counts **mislabelled** frames as well as dropped ones — the Reassoc Response bug leaves frame counts looking healthy, so dropped-only accounting would miss it.
- **Deliberately slightly wider than minimal, and why:** replay overrides the clock. `handle_packet` previously stamped rows with `time.strftime()` on the wall clock and `track_session` called `time.time()` directly. Left alone, a replayed night collapses into the seconds the replay takes — `Interval_sec` would measure our own parsing speed and `SESSION_TIMEOUT` would never fire, so `Session_Note` and the daily summary would be fiction. `_now()` returns the wall clock whenever `_CURRENT_FRAME_TIME is None`, which is always the case live, so **the live path is behaviourally identical**; `time.strftime(fmt, time.localtime(time.time()))` is exactly what the bare `time.strftime(fmt)` did.
- Verified end to end on a synthetic 48-frame pcap covering all 16 subtypes with FCS flagged. Parity reports 43.8% of management frames dropped plus 3 mislabelled; a stub `tshark` on PATH exercised the element half and correctly identified the 3 Action frames whose elements `_iter_ies()` cannot reach. Replay wrote 27 rows carrying the capture's timestamps (09:57, one hour before the 10:59 wall clock) and `Interval_sec` 4.0s, matching the 16 × 0.25s the pcap was built with — on the wall clock both would have been ~0.
- Full CI sequence green locally: `compileall` over `src archive tests` (and `scripts`, which CI does not cover), `unittest discover -p "*.py"` **132 tests** (126 + 6 new), `bash -n scripts/*.sh`. CI step 4 (`test_sniffer_v0_7.py --help`) fails on this box only because scapy is not installed here; unrelated to this change.
- Six tests added to `tests/test_night_sniffer_v3.py` as a new pair of classes — no existing test touched. They pin the live path to the wall clock, replay to capture time, `Decimal` → `float` conversion of scapy's `EDecimal`, the no-timestamp fallback, that `track_session` runs on the frame clock, and that `--out-dir` moves all three outputs.
- No dependencies added. `tshark` is an optional external tool, degraded gracefully, and comes from the same package as the `dumpcap` already used by `scripts/run_dumpcap.sh`. No git write commands run.

### Suggestions / Issues noticed
1. **An exception inside `handle_packet` costs a monitor-mode reset, and is misreported as an adapter drop.** `handle_packet` has no top-level `try/except`, and scapy's sniff loop catches any `prn` exception with a broad `except Exception` (`sendrecv.py:1366`), then **closes the socket** and removes it from the sniff set. With one interface the loop exits and `sniff()` returns normally, which `:1571` reads as "adapter dropped out of monitor mode" — so it sleeps `RETRY_DELAY`, resets the interface, and after `MAX_RETRIES` gives up. The most likely trigger is the `print()` at `:1248`: `extract_ssid` yields a `str` that may contain emoji or CJK, and under `nohup`/cron with a non-UTF-8 stdout that is a `UnicodeEncodeError`. Disk-full in `_append_csv_row` does the same. Scheduled for Phase 3, but worth knowing now if the logs already show unexplained reconnects.
2. **Throughput is the other half of the gap against dumpcap, and it is invisible.** Per frame `handle_packet` performs two full `open()`/`write()`/`close()` cycles (`:1112`, `:671`) plus a terminal print, and `sniff()` at `:1568` carries no BPF filter, so every data frame on the channel is copied to userspace and discarded in Python. `dumpcap` pushes `type mgt` into the kernel. Under load this overflows the capture ring, and scapy reports no drop counter, so the loss leaves no trace. Phase 3 covers the filter and the file handles; a drop-count readout has no clean source in scapy and may need `/proc/net/dev` or a `pcap_stats` binding.
3. **Hop mode will dominate any naive frame-count comparison against dumpcap.** At `CHANNEL_HOP_INTERVAL = 0.5` over 13 channels the radio is deaf on 12/13 of the timeline. This is not a bug and Phase 0 does not address it, but a camped dumpcap will always show more frames. **Compare like with like: run the parity script against one pcap rather than comparing two live captures.** That is the same corpus-mismatch trap that invalidated the fingerprint-v2 before/after on 2026-08-13.
4. **`generate_session_report()` names the summary from the wall clock, not the capture date.** `time.strftime('%Y%m%d')` means replaying a capture from a different night writes `daily_summary_<today>.csv`, and replaying two different nights on the same day makes the second overwrite the first (mode `"w"`). Using a separate `--out-dir` per replay avoids it entirely, which is why the `--pcap` help text recommends pairing them. Not changed — the filename is shared with the live path and that is not a drive-by decision.
5. **CI's `compileall` step does not cover `scripts/`.** `.github/workflows/ci.yml` compiles `src archive tests`, so `scripts/mgmt_parity.py` and `scripts/fingerprint_baseline.py` are unchecked. Adding `scripts` to that line is a one-word change; left alone since the workflow file is outside this task.
6. **Tag 3 in the earlier baseline is now explained, and it is not a parsing defect.** The 2026-08-13 entry flagged that only 7 of 524 MACs emitted DS Parameter Set despite 74 APs being seen, and suspected `dump_ie_details()` was dropping it. `_iter_ies()` extracts tag 3 correctly in every test above. The likelier reading is that the population is dominated by client Probe Requests, which usually omit DS Parameter Set. The `tshark` cross-check suggested there is now runnable directly via `scripts/mgmt_parity.py`, which reports tag-3 counts side by side.

## 2026-08-18 (written 11:34) Phase 1 — subtype-based classification, all 16 management subtypes

- Implemented **Phase 1** of the four-phase plan, measured against the Phase 0 harness. `scripts/mgmt_parity.py` now reports **0.0% of management frames dropped and 0 mislabelled**, from 43.8% dropped and 3 mislabelled before the change.
- **`classify_frame()` now reads the frame-control subtype field instead of testing Scapy layer classes.** The old ladder of `haslayer()` checks could only see the 12 subtypes Scapy binds a layer class to, and its ordering workaround for the response frames did not survive a capture carrying an FCS. New `MGMT_SUBTYPE_LABELS` table (`:95`) maps all sixteen subtypes; `classify_frame()` (`:1234`) looks the subtype up and returns `(None, "")` only for control and data frames, which `dumpcap -f 'type mgt'` would not have kept either.
- **Newly captured: PROBE_RESP (5), TIMING_AD (6), MGMT_7, ATIM (9), ACTION (13), ACTION_NOACK (14), MGMT_15.** Reserved subtypes get a `MGMT_<n>` label rather than being dropped — an unexpected frame is evidence. The nine pre-existing labels are unchanged, so old and new CSV rows stay comparable; a test pins them so a future rename cannot happen silently.
- **`REASSOC_RESP` is reachable again.** Verified on a synthetic capture with FCS flagged: the three subtype-3 frames that Phase 0 recorded as `ASSOC_RESP` are now `REASSOC_RESP` at the same timestamps. A row-level diff of the Phase 0 and Phase 1 replay CSVs shows exactly three Phase 0 rows no longer produced — those three — and 24 rows added (21 previously dropped, 3 relabelled). No other row changed.
- **Address resolution now falls back `addr2 → addr3 → addr1`**, so a frame with a malformed transmitter address is logged rather than discarded. `handle_packet` (`:1290`) no longer returns on an empty MAC; it returns only when the frame is not management. An unattributable frame is written to the CSV with an empty `MAC_Address` and `Session_Note` of `No-Address`, and is kept out of session tracking, since it cannot belong to a device.
- **Corrected a semantic change I introduced mid-implementation.** The uniform `addr2`-first chain silently moved `BEACON` attribution from addr3 (BSSID) to addr2 (transmitter). Identical on a normal AP, different on a repeater or mesh node — and `wifi_full_recon_report.csv` accumulates across runs, so it would have left old and new beacon rows quietly incomparable. Beacons now read addr3 first as they always have; every other subtype reads addr2 first. Caught by diffing the replay CSV against the Phase 0 one, which is precisely what the harness was built for.
- **`CLIENT_FRAME_TYPES` deliberately left unchanged.** The new subtypes are captured, fingerprinted and logged, but do not feed session tracking or the device count. Widening capture and widening the count are separate decisions, and the scorer in `_same_randomized_session_score()` was tuned against the existing six. Noted in a comment at the set's definition so the omission reads as a decision rather than an oversight.
- `extract_ssid()`'s fallback now treats `PROBE_RESP` like `BEACON` (`:1300`): a zero-length SSID element from an AP is a hidden network, from a client it is a wildcard probe.
- Dropped four imports that existed only to serve the old ladder — `Dot11ProbeReq`, `Dot11Beacon`, `Dot11AssoResp`, `Dot11ReassoResp`. `Dot11AssoReq`, `Dot11ReassoReq`, `Dot11Auth`, `Dot11Deauth` and `Dot11Disas` stay: `parse_frame_body()` still reads their fixed fields.
- **Updated six tests in `tests/claude_night_sniffer_v3.py` that encoded the old contract.** Two of them asserted the layer-ordering workaround that this change exists to remove. Each case keeps its original intent and now exercises the subtype path; `FakePacket` gained an opt-in `getlayer(Dot11)`. This is the one place the change reaches outside the task's stated scope, and it was unavoidable — those tests test the function being replaced.
- Ten tests added across the two test files: full 16-subtype coverage, the Reassoc/FCS regression, historical-label pinning, control/data rejection, both address fallbacks, the beacon addr3 preference, malformed control fields, and that an address-less frame reaches the CSV without reaching `track_session`.
- Full CI green: `compileall` over `src archive tests scripts`, `unittest discover -p "*.py"` **143 tests** (132 → 143), `bash -n scripts/*.sh`. No dependencies added, no git write commands run.

### Suggestions / Issues noticed
1. **`ACTION` frames now appear with an empty `IE_Sequence`, and that is Phase 2, not a new bug.** The parity run still reports 6 elements lost across 3 Action frames, because `_iter_ies()` anchors on `getlayer(Dot11Elt)` (`:616`) and Scapy dissects an Action frame as `Dot11 / Dot11Action / Raw` — there is no `Dot11Elt` to anchor on. The frames are captured now; their elements are not. Phase 2 replaces the anchor with a subtype-driven offset into the frame bytes.
2. **Terminal output volume will rise sharply and `--frames no-beacon` will not contain it.** Probe Responses are AP-originated and roughly as common as Probe Requests, and they are tagged `[A]`, but the flag only suppresses `BEACON` by name. If the live terminal becomes unusable, the cheap fix is a third `--frames` choice — `client-only`, keyed on the existing `CLIENT_FRAME_TYPES` — rather than redefining what `no-beacon` means. Not added; it changes the CLI contract.
3. **The Action category is the single most valuable field now going unrecorded.** Category 5 (Radio Measurement), 6 (Fast BSS Transition) and 10 (WNM) distinguish roaming behaviour that nothing else in the CSV captures, and it is one byte at a known offset. It needs a column though, and `CSV_FIELDS` has held at 25 through both change sets — worth deciding deliberately rather than folding into `Note`.
4. **`MGMT_7` and `MGMT_15` appearing in a real capture would be worth investigating, not ignoring.** Those subtypes are reserved; frames carrying them are typically malformed, from a non-conformant device, or a sign of an injection tool nearby. They are now visible instead of silently discarded, which is the point, but nothing flags them.
5. Restating from the Phase 0 entry because it is now the largest remaining gap: **`handle_packet` still has no top-level `try/except`**, so one exception costs a monitor-mode reset that gets logged as an adapter drop. Phase 1 widened the range of frames reaching that code — including reserved and malformed subtypes that were previously discarded before any parsing — so the exposure is higher now than it was yesterday. This is the first thing Phase 3 should fix.

## 2026-08-18 (written 12:12) Phase 2 — element walk re-anchored on frame geometry; one parser

- Implemented **Phase 2**. The parity harness now reports **0 frames dropped, 0 mislabelled, 0 elements missing** against the reference capture — full agreement with tshark on both frame and element coverage.
- **`_iter_ies()` no longer anchors on `getlayer(Dot11Elt)`.** New `_element_bytes()` (`:700`) computes the element region from the captured bytes and the frame's own header: `dot11.original` (what Scapy was handed, never a re-serialisation), minus the FCS when radiotap advertised one, skip the 24-byte MAC header, skip 4 more when the +HTC/Order bit is set, then skip the fixed body length for that subtype from the new `MGMT_FIXED_BODY_LEN` table. Elements are reachable for every subtype now, including the Action frames Scapy dissects as `Dot11/Dot11Action/Raw` with no element layer at all.
- **Action frames get a `(category, action)` offset table** (`ACTION_ELEMENT_OFFSETS`), because their body is Category(1) + Action(1) + category-specific fixed fields and only some categories are followed by elements. Only combinations with *unconditional* fixed fields are listed. WNM BSS Transition (category 10, actions 7/8) is deliberately excluded: its fixed part has optional fields gated by flags earlier in the same frame, so any fixed offset would be right for some frames and wrong for others.
- **The offset table cannot corrupt the CSV.** `_walk_tlvs()` takes a `strict` flag. Where the offset comes from the frame header the walk is lenient — a capture truncated by snaplen leaves a partial final element and the ones before it are still good. Where the offset comes from the table the walk is strict: it must tile the buffer exactly or nothing is recorded. A wrong table entry therefore degrades to the old behaviour (no elements) and never to invented ones. Verified with a deliberately mis-sized Action body.
- **Explicit FCS handling.** Previously the trailing checksum was discarded only as a side effect of the loop bound. `_element_bytes` strips it when the layer carries an `fcs` field, which is set exactly when radiotap flagged one.
- **`extract_ssid()` and `get_correlation_identity()` now read the same walk** — three element parsers became one. This fixes a real truncation: Scapy's `Dot11EltVendorSpecific` chain stops at the first element it cannot dissect, and vendor elements sit late in a frame, which is precisely where that bites. A test covers a vendor element behind an unknown element.
- Seven behaviours verified against real scapy on hand-built frames: FCS stripped rather than walked, +HTC offset honoured, truncated final element keeps the earlier ones, strict gate rejects a bad Action layout, unknown Action category records nothing, non-management frames ignored, vendor element payload includes its OUI.
- Dropped the now-unused `Dot11Elt` and `Dot11EltVendorSpecific` imports. `Dot11` plus the five layers `parse_frame_body()` reads fixed fields from are all that remain.
- Full CI green: `compileall`, `unittest discover -p "*.py"` **147 tests** (143 → 147), `bash -n scripts/*.sh`. No dependencies added, no git write commands run.

### The WMM/WPS misattribution — found, and fixed because the repo's own test demanded it

- **Any device advertising a WMM or WPS element was being reported as `Microsoft (Surface/WPS)`.** Confirmed against real scapy before any change: a probe request carrying only `00:50:F2` type 2 (WMM) or type 4 (WPS) returned `Microsoft (Surface/WPS) (Unknown)`.
- Cause: `get_correlation_identity()` read `vendor_type = info[0]`, but `Dot11Elt.pre_dissect` sets `info` to the element's **full** payload including the three OUI octets — so `info[0]` was always `0x00`, never `0x02` or `0x04`. The `is_wmm_or_wps` guard could never fire, and `KNOWN_OUIS["00:50:f2"]` then supplied the Microsoft label. The guard has been dead since it was written.
- **It survived because its own test used an unrealistic fixture.** `test_wmm_vendor_tag_does_not_imply_windows_or_microsoft` passed `VendorNode(0x0050F2, info=b"\x02")` — `info` *without* the OUI, which is not what scapy returns. Under that fake the guard fired and the test passed; under real scapy it never did.
- Fixed as `info[3] if len(info) >= 4 else None`. This is the one behaviour change in Phase 2 that was not a pure refactor, and it was taken because **the repo's own checked-in test specifies it**: the test asserts WMM must not imply Microsoft, and correcting the fixture to real wire bytes would otherwise have turned it red. Code and test now agree for the right reason.
- **Effect on data:** devices whose only vendor element is WMM or WPS no longer resolve to Microsoft; they fall back to their MAC OUI, or to `Unknown` for a randomized MAC. This changes the `Note`/`Session_Note` columns and `Session.fingerprint`. It does **not** reach the merge scorer — `identity` is not one of its inputs — so device counts are unaffected. To revert, restore `info[0]`.
- The rest of the port is faithful: verified before the fix that the ported function returned byte-identical identities to the layer-chain version on the same frames.
- Test fixtures rewritten to build real TLV bytes (`tlv()`, `vendor_tlv()`, `mgmt_wire()`, `WirePacket`), replacing `IdentityPacket`, `SsidPacket`, `RawIePacket` and `VendorNode`. Four tests added: WPS as well as WMM, a vendor element behind an unknown element, a zero-length SSID, and an SSID past a beacon's 12-byte fixed body.

### Suggestions / Issues noticed
1. **`ACTION_ELEMENT_OFFSETS` is marked *verify* and should be checked against a real capture.** The values come from IEEE 802.11-2020, not from measurement. The strict gate makes a wrong entry harmless — it yields no elements — but a silently-empty column looks the same as a category that genuinely carries none. `scripts/mgmt_parity.py` will name the gap: any Action-carried tag tshark sees and the tool does not shows up in the missing column.
2. **WNM BSS Transition elements are still unreachable, and that is the largest remaining element gap.** Category 10 actions 7 and 8 carry Neighbor Report elements listing roam candidates — genuinely useful for tracking movement between APs. Reaching them means parsing the conditional fixed fields (BSS Termination Duration, Target BSSID) rather than using a fixed offset. Worth doing only if the capture shows meaningful volume.
3. **The tag-50 misreading called out on 2026-08-13 is still live and was carried across unchanged.** `get_correlation_identity()` reads tag 50 as a channel list to infer region, but tag 50 is Extended Supported Rates; tag 36 is Supported Channels. Rate byte 12 is 6 Mbps, near-universal, so the `TH/EU` branch likely fires for most devices regardless of region. Deliberately preserved during the port so Phase 2 stayed a refactor. It is a one-token change (`50` → `36`) whenever you want it, but it will move the `region` string on most rows.
4. **`_last_seen` still grows without bound.** Every MAC ever seen stays in the dict for the life of the process, and Phase 1 widened what reaches it. On a long overnight run with randomized MACs this is a slow leak. `_expire_sessions()` already has the pattern to copy.
5. Restated once more, now the only item left from the original four-phase plan: **`handle_packet` has no top-level `try/except`**, and one exception costs a monitor-mode reset logged as an adapter drop. Phase 3 covers it along with the BPF `type mgt` filter and holding the CSV handles open.

## 2026-08-18 (written 12:41) Phase 3 — frame-loss guards: BPF filter, held-open handles, callback guard

- Implemented **Phase 3**, the last of the four-phase plan. Three independent frame-loss mechanisms closed.
- **`handle_packet()` now absorbs and counts exceptions** instead of letting them reach Scapy. It is a thin wrapper around the renamed `_process_frame()`. This was the worst of the three: Scapy's sniff loop catches any exception escaping the packet callback with a broad `except Exception`, **closes the capture socket** and removes it from its socket set, so with one interface `sniff()` returns normally — which main() reads as the adapter dropping out of monitor mode. One malformed frame cost a monitor-mode reset and `RETRY_DELAY` seconds of blindness, and `MAX_RETRIES` of them ended the run, all reported as a hardware fault. The first `MAX_FRAME_ERROR_LOGS` (5) are logged in full, the rest counted, and the total reported at shutdown. `except Exception` does not catch `KeyboardInterrupt`, so Ctrl+C still stops the capture — covered by a test.
- **The terminal print is separately guarded against `UnicodeEncodeError`.** SSIDs are arbitrary bytes and routinely hold emoji or CJK; under `nohup` or cron stdout is often not UTF-8. Verified with an ASCII-only stdout and an SSID of `café☕`: the terminal line is skipped and the frame still reaches the CSV with the SSID intact. This was the most likely trigger of the reset described above.
- **`filter="type mgt"` is now applied to live capture**, matching `scripts/run_dumpcap.sh`. Every data frame on the channel was previously copied into userspace only to be discarded in Python, and that wasted throughput is what overflows the capture ring under load — losing management frames with no counter to show it. This narrows what the process sees, so it sits inside the passive-capture rule rather than against it.
- **The filter fallback distinguishes setup failure from a later adapter drop.** `sniff_filtered()` counts delivered frames; if the filter is refused before any frame arrives it warns and retries unfiltered, but once frames have flowed a later exception is re-raised to the existing retry logic. Silently dropping the filter there would have masked a real fault. Note that Scapy needs libpcap or tcpdump to compile a BPF at all — if neither is present the run continues unfiltered with a warning rather than failing.
- **No BPF filter on the replay path.** A file has no capture ring to protect, `_process_frame()` already ignores non-management frames, and Scapy's offline filter path shells out to `tcpdump` — which would have made replay depend on a tool the live path does not need. Caught during testing when replay emitted a spurious "not in monitor mode" warning about a filename.
- **Both reports are held open and flushed per row** rather than opened, written and closed once per frame — four syscalls per frame per file, on an SD card, at beacon rates. Flushing after each row keeps `tail -f` and a hard power-off both seeing every row written. `setup_ie_csv()` drops any cached handle before truncating, since a stale append handle would write past a hole at the old offset. `close_output_files()` runs at the end of both the live and replay paths.
- Six behaviours verified against real scapy, and six tests added covering the same ground: exception absorbed and counted, log capped while counting continues, `KeyboardInterrupt` propagating, handle reuse and shutdown close, rows visible to a reader immediately, and the IE-report truncation dropping its handle.
- Full CI green: `compileall`, `unittest discover -p "*.py"` **153 tests** (147 → 153), `bash -n scripts/*.sh`. No dependencies added, no git write commands run.

### Final state after all four phases

- Against the reference capture the parity harness reports **0 of 48 management frames dropped, 0 mislabelled, 0 of 198 elements missing** — full agreement with tshark on frame and element coverage. Before Phase 1 the same capture lost 43.8% of frames and 3 more were recorded under the wrong type.
- Test count 126 → **153**. No dependencies added at any point. Nothing committed; the working tree is the deliverable.

### Suggestions / Issues noticed
1. **The BPF filter is unverified on the Pi and should be checked on the first live run.** If libpcap is not reachable from Scapy the log will say so and capture continues unfiltered — correct, but without the throughput benefit that motivated the change. Confirm the warning is absent, then compare CPU against a pre-change run.
2. **There is still no capture-drop counter.** The filter reduces the pressure that causes kernel ring overflow but cannot prove it worked; Scapy exposes no `pcap_stats`. Until something reads it, "we are not dropping frames" stays an inference. Reading `/proc/net/dev` around the capture, or a small ctypes binding to `pcap_stats`, would settle it.
3. **Flushing per row was chosen over a timed flush deliberately** — it keeps the syscall saving from holding the handle open while preserving immediate visibility, which the existing CSV tests rely on and which `tail -f` needs. If profiling on the Pi shows flush cost dominating, a time-based flush is the next step, but it trades away crash-durability.
4. Carried forward unresolved, in the order I would take them: the **tag-50/tag-36 region misreading** (one token, moves the `region` string on most rows); **`_last_seen` growing without bound** over a long overnight run; **`ACTION_ELEMENT_OFFSETS` still marked *verify*** against a real capture; and **WNM BSS Transition elements** still unreachable behind conditional fixed fields.
5. **The four phases were validated almost entirely against a synthetic capture.** It covers all sixteen subtypes and the awkward cases deliberately, but it is not a real RF environment — no truncated frames from snaplen, no vendor elements from real silicon, no malformed frames from non-conformant devices. **Run `scripts/mgmt_parity.py` against a real `dumpcap` capture before trusting any of these numbers**; that is what it was built for, and it is the one step in the plan that this dev box cannot do.

## 2026-08-18 (written 13:05) Follow-up — stop discarding bytes with no known layout

- Corrected a wrong call I made across all three phases. Where a frame region had no layout I recognised, I returned `b""` and the bytes were gone. That was me deciding data with no current use is not worth keeping; it is not my decision, and the requirement is to capture everything in management frames and interpret later.
- **Regions that were being discarded and are now kept:** reserved subtypes 7 and 15 bodies; Action frames whose `(category, action)` has no entry in `ACTION_ELEMENT_OFFSETS` (e.g. category 127 Vendor Specific); Action WNM category 10 actions 7/8, excluded from the offset table because their fixed part has flag-gated optional fields; bytes trailing a snaplen-truncated element; and the fixed parameters of every subtype, which were never recorded at all.
- **`_element_bytes()` replaced by `_frame_parts()`**, returning a frozen `FrameParts` dataclass with `header`, `fixed`, `elements`, `unparsed` and `fcs`. The invariant is that `header + fixed + elements + unparsed + fcs` reconstructs the frame exactly. Anything not attributable lands in `unparsed` rather than being dropped. Verified byte-exact across all 48 frames of the reference capture and pinned by tests.
- `_walk_tlvs()` now returns `(elements, consumed)` instead of `list | None`. The caller compares `consumed` against the buffer length to decide whether the region tiled; leftovers are the caller's to keep. The strict/lenient distinction is unchanged in effect — a table-derived Action offset must still tile exactly — but a rejected candidate now becomes `unparsed` instead of `b""`.
- **`dump_ie_details()` writes one row per body *region*, not just per element.** Non-element regions use negative pseudo-IDs so `IE_ID < 0` selects them all: `-1` "Fixed Parameters" and `-2` "Unparsed Bytes". New `_decode_fixed()` labels the fixed parameters where it is cheap and unambiguous — Action category name and action code, beacon interval and capability, auth algorithm/sequence/status, reason codes, AID. A frame body rebuilds from the report as `IE_ID + IE_Length + IE_Raw_Hex` for element rows and `IE_Raw_Hex` alone for pseudo-ID rows; a test asserts that reconstruction is exact.
- **New `Frame_Hex` column** on `wifi_full_recon_report.csv`: the complete 802.11 frame as captured, hex-encoded, checksum included. The per-IE report is truncated every run, so it could not be the durable record. Appended **last** so no column position moved, and all three downstream readers (`estimate_devices_from_csv.py`, `scripts/fingerprint_baseline.py`, `src/randomized_session_counter.py`) use `csv.DictReader`, so none are affected. Controlled by `--raw-frames {on,off}`, default **on**.
- Scope check on `Frame_Hex`: management frames only, which is the same scope `scripts/run_dumpcap.sh` already writes to `pcap_files/`. No new collection surface — it keeps the bytes next to the decoded columns. Outputs stay gitignored.
- **Hardened the byte extraction.** `getattr(dot11, "original", b"") or bytes(dot11)` would raise on a layer that cannot be re-serialised, and after Phase 3 that exception is swallowed by the frame guard — so the frame would vanish silently, which is exactly the failure mode being removed. The `bytes()` fallback is now guarded.
- **The Phase 3 guard was masking test failures.** Two handler tests reported unrelated assertion errors because `_process_frame` raised and `handle_packet` absorbed it. Both now call `_process_frame` directly; they test frame processing, not the guard, and the guard has its own tests.
- A test I wrote asserting `IE_Raw_Hex` concatenates to the body was **wrong and caught a real subtlety**: element rows store the payload, with tag and length in their own columns. Nothing is lost, but reconstruction needs all three. Fixed the assertion, not the code, and documented the reconstruction rule.
- Six tests added (`NightSnifferV3LosslessTests`): region round-trip across five subtypes, reserved-subtype body kept, unknown Action category kept, trailing bytes after a truncated element kept, IE-report rows reconstructing the body, and `Frame_Hex` holding the whole frame.
- Full CI green: `compileall`, `unittest discover -p "*.py"` **159 tests** (153 → 159), `bash -n scripts/*.sh`. Parity unchanged at 0 frames dropped, 0 mislabelled, 0 elements missing. No dependencies added, no git write commands run.
- Wrote `explanation/20260818-1301-capture-everything-what-changed-and-how-to-use-it.md` — what changed and why across all three phases plus this pass, the WMM/WPS behaviour change, and how to run every flag.

### Suggestions / Issues noticed
1. **`Frame_Hex` will dominate the CSV size.** On the 48-frame synthetic capture it took the file from 11.1 KB to 18.9 KB, and that capture has short bodies; real beacons are far longer, so expect a larger multiple overnight. It is on by default because the instruction is to capture everything, but watch the SD card on the first long run and use `--raw-frames off` if it becomes a problem.
2. **`Frame_Hex` and `pcap_files/` now overlap.** If `run_dumpcap.sh` is running alongside, the same frames are on disk twice in different formats. Not wrong — the pcap is the better archival format and the CSV is the queryable one — but worth a deliberate decision about which is the record of truth before both grow.
3. **`_decode_fixed()` is best-effort by design.** It names only the cheap unambiguous fields; the full bytes are in `IE_Raw_Hex` on the same row, so anything it does not decode is still recoverable. Adding decodes there is now a safe, additive change that cannot lose data.
4. The reserved-subtype rows are the ones to look at first on a real capture. `MGMT_7` and `MGMT_15` frames are typically malformed, from a non-conformant device, or a sign of an injection tool nearby — previously invisible, now recorded with their bodies intact.

## 2026-08-19 (written 10:43) Flipped the `--raw-frames` default to off

- `Frame_Hex` is no longer populated by default. Requested after discussing IE fingerprinting; the column stays in `CSV_FIELDS` so no column position moves and existing readers are unaffected — rows now carry an empty value there.
- **`src/night_sniffer_v3.py:2140` is the switch that matters.** `main()` unconditionally assigns `CAPTURE_RAW_FRAMES = args.raw_frames == "on"` at `:2167`, so the module-level constant at `:275` is overwritten on every run through `main()` — live and replay alike. Changing only `:275` would have looked correct and done nothing.
- Changed both anyway so the two agree: `:275` `True` → `False`, and the argparse `default` `"on"` → `"off"`. Also updated the `CSV_FIELDS` comment at `:267` and the `--raw-frames` help text, both of which stated the old default and would now be wrong.
- Re-enable per run with `sudo python3 night_sniffer_v3.py --raw-frames on`. No launcher in `scripts/` passes the flag, and no test reads `CAPTURE_RAW_FRAMES`, so nothing else had to change.
- CI green: `compileall` OK, `unittest discover -s tests -p "*.py"` **159 tests**, unchanged from before. No dependencies added, no git write commands run.

### Suggestions / Issues noticed
1. **The bytes are now only in `pcap_files/`** if `scripts/run_dumpcap.sh` is running alongside. That resolves the duplicate-storage question raised on 2026-08-18 in favour of the pcap being the record of truth — but it also means that if dumpcap is *not* running, anything the decoded columns miss is gone at capture time and unrecoverable. Worth deciding deliberately rather than by default.
2. **`ie_details_report.csv` still holds per-element raw hex** (`IE_Raw_Hex`), so element-level bytes survive this change. That file is truncated every run, so it is not a durable substitute for `Frame_Hex`.

## 2026-08-19 (written 11:17) Wrote the complete walkthrough of `src/night_sniffer_v3.py`

- New document: `explanation/20260819-1110-night-sniffer-v3-complete-walkthrough.md` — 762 lines, 12 sections. Written to be read by another Claude picking the file up cold, and to be explained from. No code was changed.
- **Structure:** hard constraints from `CLAUDE.md` first (section 1), the three-idea mental model (3), an end-to-end trace of one frame through the code (4), then a section-by-section reference covering every function and constant (5), the three output files (6), invariants (7), a quick reference for flags/commands/verification (8), known gaps (9), a "where to look first, by task" index (10), and links to related docs (11).
- **Every claim is anchored to a line number**, and the anchors were machine-verified: a checker extracted all 57 symbol-to-line citations from the finished document and confirmed each symbol appears within ±2 lines of the cited number in the source. Nine anchors had drifted during writing and were corrected before the check passed. Section 0 includes the `ast` one-liner to re-derive line numbers when they move again.
- Documented as facts of the current state, not as proposals: the `--raw-frames` two-definition trap (`:275` vs `:2140`), the fingerprint's all-or-nothing scoring and the band split it causes, `seq_delta()` being fully written and called from nowhere, RSSI being double-counted through `zone`, `_last_seen` growing unbounded, the live/replay bootstrap duplication and its padding-only difference, `ACTION_ELEMENT_OFFSETS` still marked *verify*, and the `Session.fingerprint` vs `Session.ie_fingerprints` naming trap.
- **One new bug found while writing** and recorded as 9.2 — see below. It was already noted in the 2026-08-18 log as "tag-50/tag-36 region misreading"; this pass established why it fires on nearly every row rather than occasionally.
- No code changed, so no tests were re-run for this entry; the suite was green at 159 tests earlier the same day.

### Suggestions / Issues noticed
1. **The region misread (`:1214-1216`) is worse than "one token".** It reads tag 50 (Extended Supported Rates) as a channel list and tests for 12 or 13. Rate byte `0x0c` is 12 and means 6 Mbps non-basic, which nearly every OFDM-capable device advertises — so the test passes on most devices and `region` reads `TH/EU` almost always, rather than occasionally. The correct tag is 36 (Supported Channels), already in `IE_NAMES` at `:294`. Fixing it changes the `Note` column on most existing rows, so it needs a deliberate decision about comparability with historical CSVs.
2. **Section 9 is now the single consolidated list of open issues.** It was assembled from the per-entry "Suggestions / Issues noticed" sections across this log plus fresh verification against the current file. If an item there gets fixed, that section should be updated rather than leaving the document to drift.
3. **The document will go stale on line numbers first.** Section 0 carries the re-derivation snippet for that reason, but a structural change to `main()` or the parser would need a real revision, not just renumbering.

## 2026-08-24 (written 15:18) TASK S1 — Logstash shipping sink (Pi side)

Implements `prompts/TASK_S1_logstash_shipping_pi.md`. Additive and opt-in: a run
without `--ship` behaves exactly as before. **Written under explicit human sign-off
for the `CLAUDE.md` off-device-forwarding rule — see the governance note below.**

- **New file `src/ship_logstash.py`** (174 lines): `shipping_enabled()`,
  `init_shipper()`, `ship_row()`, `ship_stats()`, `close_shipper()`. Imports
  cleanly without `python-logstash-async` — the import sits in a `try/except
  ImportError` and `init_shipper()` reports the missing dependency instead.
- **Eight edit sites in `src/night_sniffer_v3.py`** (+57 / −2 lines):
  1. `:29` — `import ship_logstash`
  2. `:112-124` — `SHIP_HOST` / `SHIP_PORT` / `SHIP_DB_PATH` constants block
  3. `:1834-1852` — `_process_frame()`: row list bound to `row`, guarded
     `ship_logstash.ship_row(dict(zip(CSV_FIELDS, row)), ...)` **after**
     `_append_csv_row(row)`, before `dump_ie_details(...)`
  4-6. `:2186-2202` — `--ship`, `--ship-host`, `--ship-port` argparse flags
  7. `:2215-2224` — `init_shipper()` after `apply_output_dir()`, before the
     `--pcap` branch, so replay ships too; `SystemExit(1)` when it fails
  8. `:2295-2296` — startup log line, and `ship_logstash.close_shipper()` added
     after `close_output_files()` at both shutdown sites (`:2110` in
     `run_replay()`, `:2391` in `main()`)

**Preconditions — all six verified before editing, all passed:**

- `CSV_FIELDS` length **26**, row list passed to `_append_csv_row()` length **26**,
  same order. Neither changed. (TASK_S1 and TASK_1 both describe this as 25; the
  file has held 26 since `Frame_Hex` was added.)
- `_process_frame()` ends with the inline `_append_csv_row([...])` followed by
  `dump_ie_details(...)` — confirmed before the edit.
- `close_output_files()` at exactly two call sites.
- `apply_output_dir()` called before the `--pcap` branch (`:2213` vs `:2229`).
- `logging.basicConfig()` at module level `:392` — so `propagate = False` in
  `init_shipper()` is genuinely load-bearing.
- No `CSV_FIELDS` name collides with a `LogRecord` attribute (checked all 26
  against a live `LogRecord.__dict__` plus `message`/`asctime`): **none**.

**Verification — partial. Stages A, B and C were NOT run.** They cannot be run
from the machine this was written on:

- This is WSL2 x86_64, not the Pi. `ip -br link` shows `lo`, `eth0`, `docker0`
  only — there is no `wlan1`, so Stage C is impossible here.
- `pcap_files/` contains only `.gitkeep`. Stages A and B both require
  `--pcap pcap_files/<some>.pcapng`; with no capture file there is nothing to
  replay. **The Stage A step-1 JSON envelope therefore does not exist yet and is
  not recorded in this entry.** It remains the open input for the ELK-side task.
- `python-logstash-async` is not installed and was deliberately not installed or
  pinned (human decision): the Pi is where it runs, so the version should be
  resolved and pinned there. `requirements.txt` is unchanged.
- Consequently `database_path=None` has **not** been confirmed acceptable to the
  library, and `extra_prefix=None` has **not** been validated against a real
  envelope. Both remain assumptions carried from the task document.

What was verified locally:

- `python -m compileall -q src archive tests` — OK.
- `PYTHONPATH=src python -m unittest discover -s tests -p "*.py"` — **159 tests,
  OK**, unchanged from the pre-edit baseline.
- A scratchpad harness stubbing scapy the same way `tests/` does confirmed: the
  three flags parse with defaults `127.0.0.1` / `5000`; `shipping_enabled()` is
  `False` by default and `ship_row()` is a silent no-op that leaves counters at
  `(0, 0)`; `close_shipper()` is a no-op when never initialised;
  `init_shipper()` returns `False` with the dependency absent (which `main()`
  turns into `SystemExit(1)`); `dict(zip(CSV_FIELDS, row))` yields 26 distinct
  keys with no collisions; the ship call sits after `_append_csv_row(row)` and
  before `dump_ie_details(...)`; `close_output_files()` precedes
  `close_shipper()` at both exits.

**`FINGERPRINT_VERSION` was NOT bumped** — still 2. Nothing about the hash input,
`CSV_FIELDS`, `IE_CSV_FIELDS`, or any column value changed.

**TASK 1 and TASK 2 confirmed still on hold and untouched:** `LOG_FILE` remains
the single fixed constant at `:43`; there is no `LOG_DIR`, `LOG_PREFIX`, or
`build_log_path()`; there is no `Timestamp_ISO` column and no read of `pkt.time`.

No dependencies added. No git commands beyond read-only `diff`/`status` were run.

### Suggestions / Issues noticed

Carried from TASK_S1's seeded list, all still unaddressed and none acted on:

1. **`@timestamp` is record-creation time, not capture time.** The formatter
   stamps the event when `ship_row()` runs, so Kibana's primary time axis is
   callback time. TASK 2 exists to fix this on the CSV side; once it lands the
   shipper should override `@timestamp` from `Timestamp_ISO`.
2. **Mixed-type fields will break Elasticsearch dynamic mapping.** `Channel` is
   an `int` normally and the string `"N/A"` when radiotap carries no channel;
   `Power_dBm`, `Distance_m`, `Interval_sec`, `Seq_Num`, `Listen_Interval`,
   `Cap_Info`, `Auth_Status` and `Reason_Code` are `None` on some subtypes. This
   must be solved with an index template on the ELK side — transforming values
   here would break the CSV↔event 1:1 property the whole test rests on.
3. **No document ID.** A replay of the same pcap creates a second full set of
   documents. Needs a decision (frame hash, or `sensor_id`+time+seq) before
   anything long-lived.
4. **No `sensor_id`.** RPi 3B and RPi 4 events are indistinguishable in the
   index. The formatter's `host` field may suffice — confirm from the Stage A
   envelope rather than assuming.
5. **Beacon volume.** Every row ships and beacons dominate; `--frames no-beacon`
   affects only the terminal, not shipping. Measure events/sec from an existing
   CSV before sizing downstream.
6. **Raw MACs leave the device unredacted on this path.** Signed off explicitly
   by the human before this code was written. `CLAUDE.md`'s "no forwarding of
   raw captures off-device" rule now contradicts shipped behaviour and should be
   amended to record the exception, so the next reader is not left resolving a
   rule against the code.
7. **In-memory spool loses queued events on process death.** With
   `SHIP_DB_PATH = None` a `SIGKILL` or power loss drops whatever the worker has
   not sent, bounded by `SHIP_FLUSH_INTERVAL`. There is still no SIGTERM
   handler, so `systemctl restart` does not call `close_shipper()` either — the
   shutdown wiring only covers Ctrl+C, retry exhaustion, and replay completion.
8. **Default `--ship-host` is `127.0.0.1` by design.** An accidental `--ship`
   sends to a local listener, not to a real host. Worth keeping that way.

## 2026-08-24 (written 16:45) TASK S1 Stage A — PASSED, run on WSL2 rather than the Pi

Completes the verification left open by the 15:18 entry. Code unchanged — this
entry records verification results only. Commit `4716608` is the code under test.

**Stage A does not need the Pi.** `run_replay()` calls
`sniff(offline=pcap_path, prn=..., store=False)` at `:2097`: no interface is
opened, no channel tuned, and there is no root check anywhere in the file. So the
replay runs as an ordinary user on any Linux box, and the runbook's
"whichever Python `sudo` invokes" venv problem does not apply to this stage.
Stage B still needs the library on the Pi, since it tests the Pi→WSL2 network path.

**Environment (WSL2, x86_64, Python 3.12.3).** `ensurepip` is absent
(`apt install python3.12-venv` would be needed), so pip was bootstrapped into
`.venv` from PyPA's `get-pip.py` — no sudo, no change to system Python.
`.venv/` was already gitignored at `.gitignore:7`.

- **`python-logstash-async` version: 4.1.0**
- `scapy 2.7.0` and `mac-vendor-lookup 0.1.15` — both match the existing
  `requirements.txt` pins. `requirements.txt` was NOT modified; the Pi should
  resolve and pin its own version.

**`database_path=None` is accepted by 4.1.0.** `init_shipper()` returned True and
logged `(spool: memory)`. This was an open question in the 15:18 entry.

**`extra_prefix=None` is validated, not assumed: all 26 CSV fields arrive at the
top level.** No `"extra"` nesting. This was the step the task doc explicitly said
to verify with netcat rather than assume.

### Stage A results — input `pcap_files/20260824-1357-dumpcap-rpi6-pre-ship.pcap`

| Measure | Value |
| --- | --- |
| frames read from pcap | 3163 |
| CSV data rows | **3163** |
| lines received by listener | **3163** |
| `Shipping totals` queued / failed | 3163 / 0 |
| unparseable JSON lines | none (3163 parsed) |
| field-for-field CSV vs shipped, row 1 | **0 differences** |
| negative check (`--ship` vs no `--ship`) | CSV data rows **identical**, diff empty |

Frame-type mix in the sample: BEACON 1817, ACTION 1075, PROBE_RESP 149, PROBE
116, AUTH 2, DISASSOC 1, DEAUTH 1, REASSOC_REQ 1.

### The netcat trap — why the first Pi attempt failed

The Pi run reported `3163 queued, 0 failed` while delivering almost nothing, with
`[Errno 111] Connection refused` and `[Errno 107] Transport endpoint is not
connected`. Cause: **python-logstash-async opens a new TCP connection per flush
batch**, and `nc -l` accepts exactly one connection then exits. Every batch after
the first hit a closed port. Reproduced locally: connection 1 sent, connections 2
and 3 refused, 1 line captured.

This run used a reconnect-tolerant listener instead and logged **64 connections**
for 3163 events — direct confirmation of the per-flush reconnect behaviour.
`socat -u TCP-LISTEN:5000,reuseaddr,fork ...` or `ncat -k -l 5000` work equally
well; plain `nc -k` only on some builds.

### Stage A step 1 — the JSON envelope, verbatim

First event of the run, as received on the wire:

```json
{
    "@timestamp": "2026-08-24T09:40:49.973Z",
    "@version": "1",
    "host": "TCCTN-21704",
    "level": "INFO",
    "logsource": "TCCTN-21704",
    "message": "BEACON D8:76:AE:13:9D:50",
    "pid": 103024,
    "program": "src/night_sniffer_v3.py",
    "type": "night_sniffer",
    "Timestamp": "2026-08-24 13:57:34",
    "Pkt_Type": "BEACON",
    "MAC_Address": "D8:76:AE:13:9D:50",
    "Device_Type": "Real",
    "Vendor": "HUAWEI TECHNOLOGIES CO.,LTD",
    "SSID": "Terabitz",
    "Channel": 116,
    "Band": "5GHz",
    "Power_dBm": -52,
    "Distance_m": 3.69,
    "Interval_sec": 0.0,
    "IE_Sequence": "0,1,3,5,7,32,35,70,45,61,127,191,192,195,201,255,255,255,255,255,255,221,221,221,221,221",
    "IE_Fingerprint": "fp2:a6c3271006955de6",
    "Vendor_IEs": "00:50:f2;00:e0:fc",
    "Capabilities": "EHT;EXT106;EXT38;EXT39;EXT_CAP;HE;HT;VHT",
    "Note": "Huawei Technologies (Unknown)",
    "Session_Note": "AP-Logged-Only | Huawei Technologies (Unknown)",
    "Seq_Num": 2718,
    "Listen_Interval": null,
    "Cap_Info": null,
    "Current_AP": null,
    "Security_Tier": null,
    "Auth_Status": null,
    "Reason_Code": null,
    "Direction": null,
    "Frame_Hex": "",
    "func_name": "ship_row",
    "interpreter": "/home/phumvitw/projects/Wi-Fi-Sniffer/.venv/bin/python",
    "interpreter_version": "3.12.3",
    "line": 137,
    "logger_name": "night_sniffer.ship",
    "logstash_async_version": "4.1.0",
    "path": "/home/phumvitw/projects/Wi-Fi-Sniffer/src/ship_logstash.py",
    "process_name": "MainProcess",
    "thread_name": "MainThread"
}
```

**18 envelope keys arrive on top of the 26 CSV columns**: `@timestamp`,
`@version`, `func_name`, `host`, `interpreter`, `interpreter_version`, `level`,
`line`, `logger_name`, `logsource`, `logstash_async_version`, `message`, `path`,
`pid`, `process_name`, `program`, `thread_name`, `type`.

**`@timestamp` vs `Timestamp`, measured.** Capture time was `13:57:34 +07`
(= `06:57:34Z`); `@timestamp` is `09:40:49Z` — the moment the replay ran, **2h43m
later**. On a live capture the gap is small but non-zero; on any replay it is
arbitrary. Confirms the defect noted at 15:18.

**`host` and `logsource` both carry the hostname** (`TCCTN-21704` here). That
partly answers the missing-`sensor_id` question: two Pis are distinguishable *if*
their hostnames differ. Check `hostnamectl` on the RPi 3B and RPi 4 before
relying on it.

### Per-field JSON types across all 3163 events

Six fields are mixed, and **all six are `null` vs a single concrete type**:
`Auth_Status` (null 3161 / int 2), `Cap_Info` (null 3162 / int 1), `Current_AP`
(null 3162 / str 1), `Direction` (null 3159 / str 4), `Listen_Interval`
(null 3162 / int 1), `Security_Tier` (null 3161 / str 2). Elasticsearch ignores
nulls when inferring a mapping, so **these are not a mapping hazard** — a
correction to the concern as originally stated.

The real hazard is `Channel` and `Band`, which the code emits as the string
`"N/A"` when radiotap carries no channel. **This capture contains no `N/A` at
all** — `Channel` was int `116` and `Band` `"5GHz"` on all 3163 rows, because
every frame carried radiotap channel info. So the hazard is **latent, not
visible in this sample**: a template inferred from this pcap alone would type
`Channel` as `long`, and the first `N/A` frame in production would be rejected.
Confirmed reachable by shipping a synthetic `"N/A"` row through the real handler —
it went out as a JSON string.

### Suggestions / Issues noticed

Additions to the standing list. None acted on.

1. **`ship_stats()` cannot detect a delivery failure, and Stage C's criterion
   depends on it.** `_shipped` increments right after `_ship_logger.info()`
   returns, which only enqueues; delivery happens on the worker thread and is
   reported through the `logstash_async` logger, never back to the counter. The
   Pi run scored `3163 queued, 0 failed` having delivered almost nothing.
   TASK_S1's Stage C acceptance test — *"queued count equals the CSV row count
   and failed is 0"* — **would pass a completely dead sink.** Stage C should
   compare an Elasticsearch document count against the CSV row count, the way
   Stage A compares `wc -l`. Compounding it, `close_shipper()` logs the totals
   line *before* calling `flush()`/`close()`, so the totals can never reflect the
   final flush.
2. **`path`, `program` and `interpreter` put absolute filesystem paths in every
   document**, and `line` / `func_name` / `pid` / `thread_name` add per-event
   noise. ~200 bytes on every beacon, and it discloses directory layout to anyone
   with index access. A `remove_field` or `prune` in the Logstash filter is the
   cheap fix; it does not affect the CSV↔event 1:1 property because none of these
   are CSV columns.
3. **Beacon volume, now measured.** 1817 of 3163 events (57%) are BEACON and 1075
   (34%) are ACTION — 91% of the shipped volume is frame types that are *not* in
   `CLIENT_FRAME_TYPES` and never feed session tracking. Relevant to both index
   sizing and the separate pruning discussion.
4. **This pcap is single-channel (116, 5 GHz) and AP-heavy.** Useful as a
   deterministic Stage A input, but it exercises neither the 2.4 GHz path nor the
   `N/A` channel case, and it contains only 116 PROBE frames — so it is a weak
   sample for anything about client behaviour or session grouping.
