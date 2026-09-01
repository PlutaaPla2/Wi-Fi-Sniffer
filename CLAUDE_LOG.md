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

## 2026-08-25 (written 10:40) Governance — off-device shipping of capture data approved

Documentation only. No code changed; `src/` is untouched and still at `4716608`.

**Decision, from the human:** shipping captured data to the company framework is
approved by the PM and the senior colleague. Unredacted MACs and raw
management-frame bytes are in scope on that path. Circulation is bounded to the
Pi, the company laptop, and the company framework (Logstash, ELK, and future
company archives).

This resolves the standing constraint that had been carried unaddressed through
every TASK S1 entry and was seeded in TASK_S1's own "Suggestions / Issues
noticed" list.

**`CLAUDE.md` — "Ethical hard rules" edited**, per the section's own requirement
that relaxations carry explicit human sign-off:

- *Do not widen collection* — reworded. Now reads "no payload capture, no
  capture of data frames"; the old "no forwarding of raw captures off-device"
  clause moved out of this bullet because it was about egress, not collection.
  `Frame_Hex` / `--raw-frames on` recorded as in-scope (default stays off).
- *Captured data is PII* — replaced with an approved-perimeter rule naming the
  three destinations, the sign-off date and approvers, and an explicit
  not-approved list (public internet, third-party/cloud services, personal
  machines, git). Also records that redaction/hashing/sampling must **not** be
  added to a shipping path, since that was considered and rejected.
- Unchanged: *Passive capture only*, *Never decrypt payloads*, the `*.csv` /
  `*.pcap` gitignore requirement, and the closing STOP-and-flag rule.

**`explanation/20260825-0954-task-s1-stage-b-checkup-and-next-task-context.md`
updated** — the handoff brief for whoever designs the next task. Its "Standing
constraint, unresolved" section became "Data-handling constraint — RESOLVED",
instructing the designer not to design defensively around it. Open decision 3
(envelope fields to strip) was re-argued on cost rather than disclosure: ~200
bytes/document at 33.6 events/s is ~580 MB/sensor/day of shipper metadata, and
the disclosure argument no longer applies inside the approved perimeter.

### Suggestions / Issues noticed

1. **The perimeter is now the only thing holding the line, and nothing enforces
   it in code.** `--ship-host` accepts any address; the default `127.0.0.1` is
   the sole safeguard against an accidental send. Worth deciding whether an
   allowlist of approved destinations belongs in config. Not acted on.
2. **Retention and the "future archive" are undefined.** At 33.6 events/s per
   sensor the index grows ~2.9M documents/day/sensor with no stated retention
   policy, deletion path, or archive lifecycle. That is an ILM decision for the
   ELK-side design, and it is also the point where "PII inside the perimeter"
   becomes a question of *for how long*.
3. **TASK S1's seeded issue list still carries the old constraint** as an open
   item in `prompts/TASK_S1_logstash_shipping_pi.md`. That file is a historical
   task spec so it was left alone, but it now contradicts `CLAUDE.md`. Anyone
   reading it cold should be pointed at this entry.

## 2026-08-25 (written 11:05) TASK S1 Stage B — PASSED. TASK S1 complete.

Verification only; no code changed. `src/` remains at `4716608`.

Closes the last open item in TASK S1. Pi → WSL2 over the network, netcat only,
no Logstash involved.

### Result — input `pcap_files/20260824-1357-dumpcap-rpi6-pre-ship.pcap`

| Measure | Stage A (WSL2 loopback) | Stage B (RPi 3B → WSL2) |
| --- | --- | --- |
| frames read from pcap | 3163 | **3163** |
| `Shipping totals` queued / failed | 3163 / 0 | **3163 / 0** |
| lines received by listener | 3163 | **3163** |
| lines parsing as JSON | 3163 | **3163**, zero unparseable |
| all 26 CSV fields present, top level | yes | **yes, in every event** |
| unexpected/extra fields | none | **none** |

**Delivery was confirmed on the listener side, not from the queued counter.**
Received file was 4,167,783 bytes / 3163 lines. This matters because the queued
counter cannot detect a delivery failure (standing issue #1) — the run output
alone would have looked identical had nothing arrived.

**Provenance confirmed: `host` is `rpi6` on all 3163 events.** The events
demonstrably originated on the Pi rather than a stray local run — the check that
distinguishes a real Stage B from a repeat of Stage A. Note this also means the
Pi's hostname is `rpi6`, distinct from WSL2's `TCCTN-21704`, so the two are
separable in the index by `host` today. Still unverified for the company RPi 4.

**Frame-type mix matched Stage A exactly**: BEACON 1817, ACTION 1075,
PROBE_RESP 149, PROBE 116, AUTH 2, DISASSOC 1, DEAUTH 1, REASSOC_REQ 1,
REASSOC_RESP 1 = 3163. (The 16:45 entry's list omitted the single REASSOC_RESP
and so summed to 3162; the input was identical in both runs.)

### Two false starts worth recording

1. **An earlier attempt delivered nothing** — listener file 0 bytes. Cause: the
   Stage B reachability probe `nc -vz` connects and immediately closes, and a
   one-shot `nc -l` accepts that, sees EOF and exits. **The probe consumes the
   listener.** Reproduced deliberately: probe reported success, listener gone,
   0 bytes written. Fix is ordering — probe first, then start the listener — plus
   `nc -lk` (OpenBSD nc 1.226 on the WSL2 box supports `-k`; verified across
   three sequential connections). This compounds with the per-flush reconnect
   behaviour recorded on 08-24.
2. **An intermediate run read only 490 frames** of the same pcap and reported
   `490 queued, 0 failed`. Re-running the identical command gave 3163. Cause not
   established — a truncated or still-copying input on the Pi is the likely
   explanation. Recorded because `N queued, 0 failed` looked equally healthy at
   both 490 and 3163, which is the counter defect showing its teeth twice in one
   session.

### Envelope overhead — measured, correcting an earlier estimate

Across all 3163 events: **1318 bytes/event on the wire**, of which the
shipper-metadata envelope is **542 B/event — 44% of the JSON payload** — against
689 B of actual capture fields. The earlier "~200 bytes" figure was an estimate
and was **low by roughly 2.7×**.

At the measured 33.6 events/s this is **3.83 GB/sensor/day on the wire, 1.57 GB
of it shipper metadata** carrying no capture information. Strengthens the case
for a `remove_field` in the Logstash filter considerably.

### TASK S1 status — COMPLETE (Claude-side)

| Deliverable | Status |
| --- | --- |
| `src/ship_logstash.py` | done, `4716608` |
| 7 edit sites in `night_sniffer_v3.py` | done, all verified present |
| Preconditions verified and recorded | done |
| `CSV_FIELDS` (26) == row list (26), `:1834` | done |
| `FINGERPRINT_VERSION` unchanged (2), no column changed | done |
| JSON envelope recorded verbatim | done (08-24 16:45) |
| library version + `database_path=None` accepted | done (4.1.0) |
| TASK 1 / TASK 2 confirmed on hold and untouched | done |
| Stage A counts + negative check | done |
| Stage B counts | **done — this entry** |

Stage C remains deliberately unstarted: it needs the ELK side to exist, and its
acceptance test must be an Elasticsearch `_count`, not the queued counter.

### Suggestions / Issues noticed

Standing list unchanged and none acted on. One addition:

1. **The `nc -vz` / one-shot-listener interaction should be written into the
   runbook**, not just this log. It cost two runs, it produces a convincing
   false negative, and the next person to run a network stage will hit it.
   `prompts/RUNBOOK_S1_pi_shipping_test.md` currently gives the probe and the
   plain `nc -l` listener in that order, which is the failing order.

## 2026-08-26 12:40 TASK 2 (revised) — Capture-time ISO timestamp column

Implements `prompts/TASK_2_revised_capture_timestamp.md` in full. The superseded
`prompts/TASK_2_capture_timestamp_column.md` was **not** followed.

### Preconditions — all seven verified before editing

`CSV_FIELDS` 26 entries ending `"Frame_Hex"`; row list in `_process_frame()` 26
elements in matching order; `_frame_time()` live branch sets
`_CURRENT_FRAME_TIME = None` and returns `time.time()`; `now = _frame_time(pkt)`
followed by the `time.strftime(...)` line present; `interval` and `_last_seen`
both computed from `now`; `datetime` not imported anywhere; TASK S1 landed
(`import ship_logstash` at `:29`, `ship_row(dict(zip(CSV_FIELDS, row)), ...)` at
`:1852`). Counts recorded: **CSV_FIELDS 26 / row list 26 before, 27 / 27 after**,
confirmed by AST walk, not by eye.

### The five edit sites, all in `src/night_sniffer_v3.py`

1. `:17` — `from datetime import datetime, timezone`, after `import subprocess`.
2. `:708` — new `_capture_time(pkt, fallback)` helper, immediately after `_now()`.
3. `:283` — `"Timestamp_ISO"` appended after `"Frame_Hex"` (27 entries). The
   `Frame_Hex` comment was **updated, not deleted**: it now records that the 25
   columns above it never move and that it is followed only by appended columns.
4. `:1811` — `capture_ts = _capture_time(pkt, now)`; `timestamp` re-sourced from
   `capture_ts`; `timestamp_iso` added. Position unchanged — after the RadioTap
   block, before `dist_m`.
5. `:1894` — `timestamp_iso` appended as the final row element, after `Frame_Hex`.

### Semantic change to an existing column — recorded as one

`Timestamp`'s output **format** is byte-identical, so Excel and every existing
parser are unaffected. Its **source** changed from callback time to capture time.
Rows written before and after this change therefore carry subtly different
meanings under load: previously a frame's `Timestamp` was when the Python
callback ran, now it is when the frame arrived. Under a busy channel those differ
by the callback backlog. Anything comparing pre- and post-change rows at
sub-second granularity must know which side of this change it is reading.

### Verification step 4 — distinct-value counts, verbatim

Replay of `pcap_files/20260824-1357-dumpcap-rpi6-pre-ship.pcap`:

```
rows              : 3163
distinct Timestamp: 95
distinct ISO      : 3163
```

`distinct ISO` equals `rows` exactly, against 95 for the second-resolution
column — a 33× gain, and the fallback did not fire on a single frame. The
busiest single second holds **56 frames**, and **3068 of 3163 rows** shared a
`Timestamp` value with at least one other row; all 3163 are now separable. The
ISO column is **strictly increasing** across the whole replay, which is the
ordering property the auth/assoc handshake work was blocked on.

### Step 5 — timezone and sample value

`timedatectl` → `Time zone: Asia/Bangkok (+07, +0700)` (this WSL2 box; **the Pi's
own zone still needs recording when the live run happens**).
Sample: `2026-08-24T13:57:34.039243+07:00` — trailing offset present, six
fractional digits present.

### Step 6 — replay unaffected

3163 rows, **0 mismatches** between `Timestamp_ISO[:19]` and `Timestamp`. All 27
columns parse on every row (`wrong width: none`) via the `csv` module, not awk.
Timestamps reflect the pcap's capture date, 2026-08-24 — not the replay date.
This confirms `_frame_time()` and `_capture_time()` agree by construction under
replay, as the task assumed.

### Step 7 — the shipper carried the column with no edit

`src/ship_logstash.py` is **untouched** — it does not appear in `git status`.
Replay with `--ship` to a loopback listener: `3163 queued, 0 failed`, 3163 events
received, and **3163/3163 carry `Timestamp_ISO`**, sample
`2026-08-24T13:57:34.039243+07:00`, 3163 distinct values shipped. `dict(zip(
CSV_FIELDS, row))` did exactly what TASK S1 designed it to do. Envelope is now
45 keys. Elasticsearch `_count` was not checked — no ELK reachable from here.

### Oracle cross-check — pcapng record headers, not tshark

`tshark` is not installed on this box, so the oracle was done by parsing the
pcapng SHB/IDB/EPB blocks in pure Python — independent of Scapy, which is the
point of an oracle. 3163 EPB records against 3163 CSV rows.

**Max deviation: 0.000000715 s (715 ns). No systematic offset.** The first pcap
record and the first CSV row agree to the microsecond.

One real finding: the interface's `if_tsresol` is **9 — nanoseconds**, while the
column is written at microsecond resolution. 224 of 3163 rows differ from the
pcap header in the 6th decimal place purely from that truncation. Sub-microsecond
precision is discarded. This is recorded, **not compensated for**; it is far
below anything the handshake work needs.

### Tests

Two existing tests asserted `CSV_FIELDS[-1] == "Frame_Hex"`, an invariant this
task deliberately supersedes — `tests/claude_night_sniffer_v3.py:574` and
`tests/test_night_sniffer_v3.py:529`. Both were updated to assert what actually
must hold now: `CSV_FIELDS.index("Frame_Hex") == 25`, i.e. its **position** is
fixed and later columns are appended after it rather than inserted before it.
No other test was touched. Full CI-equivalent run: `python3 -m compileall -q src
archive tests` clean, **159 tests OK**. The repo has no configured lint command —
CI (`.github/workflows/ci.yml`) runs compileall and unittest only, so `CLAUDE.md`'s
`Lint: ...` placeholder still has nothing to fill it with.

Also unit-checked `_capture_time()` directly: `Decimal` input returns a `float`,
missing attribute / `None` / unparseable all fall back, and `pkt.time == 0`
falls back too (`not raw` is falsy on zero) — correct for 802.11 capture, where
an epoch-zero frame is a broken timestamp, not a real one.

### Scope lock — explicit confirmations

`FINGERPRINT_VERSION` **not bumped** (still 2, absent from the diff). Nothing in
the SHA-1 input changed. `_frame_time()`, `_now()`, `now`, `interval` and
`_last_seen` **not modified** — the only diff lines mentioning them are comments
and the new helper's docstring. `track_session()`, `dump_ie_details()`,
`IE_CSV_FIELDS`, the terminal `print()`, `extract_ie_details()`,
`parse_frame_body()`, `classify_frame()`, `auth_tier()`, `src/ship_logstash.py`
and the ELK repo all untouched. No second epoch-float column, no `run_id`, no
`sensor_id`. **TASK 1 remains on hold** — `LOG_FILE`, `setup_csv()` and
`_append_csv_row()`'s body are unchanged.

No git operations were run. Working tree carries three modified files for Pla2
to review and commit.

### Still outstanding — needs the Pi

Everything above is replay-mode evidence from the company laptop. The **live
capture path is unproven**: `_capture_time()` reading `pkt.time` under live
`sniff()` on the AR9271 has not been exercised, and that is precisely the path
the change exists for, since replay was already correct before it. Verification
steps 1–5 need re-running on the Pi with `--iface wlan1 --mode camp --channel 6`,
the Pi's `timedatectl` zone recorded, and a concurrent `dumpcap` + `tshark`
oracle run there. **If live `distinct ISO` comes back equal to `distinct
Timestamp`, `pkt.time` is not populated on that driver and the fallback fired —
report it, do not work around it.**

### Suggestions / Issues noticed

Standing list unchanged, none acted on. Carried forward from the task document
plus two new:

1. **The ELK pipeline still reads `Timestamp`.** Until its `date` filter becomes
   `match => ["Timestamp_ISO", "ISO8601"]` and its `timezone` setting is deleted,
   `@timestamp` stays second-resolution and the new column is dead weight in the
   index. Immediate follow-up, ELK repo, separate task.
2. **Document ID is now unblocked** — a fingerprint over `sensor_id` +
   `Timestamp_ISO` + `MAC_Address` + `Seq_Num` is safe now that ties are gone.
   The measured 3163/3163 distinct supports this directly.
3. `dump_ie_details()` still writes second-resolution timestamps, so joining IE
   rows to frame rows on `(Timestamp, MAC_Address)` stays ambiguous — measured at
   up to 56 candidate frames per second in this capture.
4. `interval` and `_last_seen` still run on `_frame_time()`. Harmless in both
   modes today; stops being harmless if session timing moves to capture time.
5. `_last_seen` still never expires — unbounded dict growth on a daemon now
   expected to run for weeks.
6. **New:** the capture interface records nanoseconds (`if_tsresol 9`) but the
   column stores microseconds. Not a defect for any current consumer, and
   `isoformat(timespec="nanoseconds")` does not exist, so raising it would mean
   leaving ISO 8601 for this column. Noted only.
7. **New:** two tests encoded "Frame_Hex is last" as the invariant rather than
   "Frame_Hex does not move". Any future appended column will break the same way
   until the assertion expresses position. Fixed here for these two; worth a look
   at whether other tests index `CSV_FIELDS` from the end.

## 2026-08-27 09:38 TASK 3 — Gate the per-IE report behind a flag

Implements `prompts/TASK_3_gate_ie_report.md` in full. TASK 2 is landed
(`e692587`), so this sits on top of it. All six preconditions verified before
editing; none triggered a STOP.

### The six edit sites, all in `src/night_sniffer_v3.py`

1. `:300` — `IE_REPORT_ENABLED = False` added after the `CAPTURE_RAW_FRAMES`
   block, with the comment recording that the report is derived data.
2. `:562` — guard as the first statement of `setup_ie_csv()`, plus a docstring
   line noting the no-op.
3. `:1168` — guard as the first statement of `dump_ie_details()`, plus a
   docstring line. The call site in `_process_frame()` was **not** touched.
4. `:2230` — `--ie-report` argument added after `--raw-frames`, mirroring its
   `choices=["on","off"] / default="off"` form exactly.
5. `:2275` — the existing global block extended to three names:
   `global TERMINAL_FRAME_FILTER, CAPTURE_RAW_FRAMES, IE_REPORT_ENABLED`.
6. `:2137` and `:2356` — both `log.info` lines now print `off` rather than naming
   a file that will not be written, each preserving its own column width
   (`run_replay()` pads labels to 32, `main()` to 30; neither was reformatted).

### Both guards are inside the functions, not at the call sites

This is the load-bearing decision. `setup_ie_csv()` opens `IE_DETAILS_FILE` with
mode `"w"` — it **truncates**. A call site that was missed would silently destroy
the report from an earlier debugging run, which is the exact failure the flag
exists to make impossible. One guard at one point of truth cannot be missed.
Verification step 4 below is the direct test of this and it passes.

The ordering requirement in 3.5 was checked, not assumed: the global block sits
at `:2275`, the `if args.pcap:` branch at `:2296`. The assignment happens before
replay is dispatched, so replay honours the flag — confirmed empirically, since
every verification run below went through `--pcap`.

### Verification — steps 1, 2, 3, 4, 6 (replay, on the company laptop)

All against `pcap_files/20260824-1357-dumpcap-rpi6-pre-ship.pcap`, 3163 frames.

**Step 1 — default is off.** Startup line reads
`Logging IE breakdown to         : off`. Directory holds
`wifi_full_recon_report.csv` and `daily_summary_20260827.csv`;
`ie_details_report.csv` is **absent**.

**Step 2 — the flag turns it on.** File present with its header row
(`Timestamp,Pkt_Type,MAC_Address,IE_Index,IE_ID,IE_Name,IE_Length,IE_Raw_Hex,IE_Decoded`),
**56 462 IE rows against the main log's 3163**.

**Step 3 — the main log is byte-identical either way.** `diff` of the two runs'
recon CSVs minus headers produced **no output**, and both files carry the same
MD5, `a8b5e51a8080a3567c9b86ac074fee63`. This is the check proving the gate
touched nothing it should not.

**Step 4 — a disabled run does not truncate an existing report.** Copied the
enabled run's report aside, re-ran with the report off into the same `--out-dir`,
`diff` against the copy produced **no output**; the file stayed 6 013 389 bytes.
The in-function guard does what it was placed there to do.

**Step 6 — shipping is unaffected.** Replay with `--ship` to a loopback listener:
`3163 queued, 0 failed`, **3163 CSV rows == 3163 events received**, envelope 45
keys with `Timestamp_ISO` present, and `ie_details_report.csv` absent throughout.
The IE report was never a shipping input; this confirms it. Elasticsearch
`_count` was **not** checked — no ELK reachable from here.

### Step 5's measured write volume — replay, not live

The task asks for measured directory sizes on and off. **This is the replay
measurement, not the live one** — the live run on the Pi is still outstanding.
Two clean runs of the same 3163-frame pcap into fresh directories:

```
off total :   1093268 bytes (1.04 MiB)
on  total :   7106659 bytes (6.78 MiB)
delta     :   6013391 bytes (5.73 MiB)  -> 6.5x
```

**The IE report is 84.6% of everything written when it is on.** Turning it off
cuts total write volume by a factor of **6.5**.

One correction to the task document's premise, which matters for the case it
makes: the report writes **17.85 rows per frame** (56 462 / 3163), not the "5–10
rows per frame" the document and the new `--help` text both state. The
justification for the task is therefore roughly twice as strong as written. The
help text was copied verbatim as instructed and **not** corrected — flagged
below instead.

### Tests — five broke, and were fixed

The task's scope-lock does not mention tests and its verification section is
entirely end-to-end, so this was not covered either way. Five existing tests call
the two gated functions **directly** and failed the moment the default became
off — predicted before editing, then confirmed exactly (3 errors, 2 failures, no
others):

| Test | File |
| --- | --- |
| `test_ie_report_rows_reconstruct_the_body` | `tests/test_night_sniffer_v3.py` |
| `test_truncating_the_ie_report_drops_the_cached_handle` | `tests/test_night_sniffer_v3.py` |
| `test_rows_match_ie_sequence_and_decode` | `tests/claude_night_sniffer_v3.py` |
| `test_setup_ie_csv_creates_header_when_missing` | `tests/claude_night_sniffer_v3.py` |
| `test_setup_ie_csv_truncates_previous_session` | `tests/claude_night_sniffer_v3.py` |

Each was fixed by adding `patch.object(..., "IE_REPORT_ENABLED", True)` alongside
the `IE_DETAILS_FILE` patch it already used. These tests cover the report's
**machinery**, which this task explicitly leaves intact — so they keep asserting
exactly what they asserted before, with the feature switched on for their
duration. No assertion was weakened or deleted.

A sixth, `test_no_information_elements_writes_nothing`, would have kept **passing
for the wrong reason**: it asserts the file does not exist, which stays true when
the report is simply disabled, whatever the frame contained. It got the same
patch, which restores its stated meaning. This was done on Pla2's explicit
instruction to fix the tests per the plan report.

Full CI-equivalent run after the fixes: `python3 -m compileall -q src archive
tests` clean, **159 tests OK**. The repo still has no lint command —
`.github/workflows/ci.yml` runs compileall, unittest, `bash -n` and a `--help`
check only.

### Scope lock — explicit confirmations

`FINGERPRINT_VERSION` **not bumped** (still 2) — nothing about the hash input
changed. `CSV_FIELDS` **unchanged at 27 entries**; `IE_CSV_FIELDS` unchanged at 9.
**No IE machinery was deleted** — `IE_NAMES`, `_decode_ie()`, `_decode_fixed()`,
`ACTION_CATEGORY_NAMES`, `PSEUDO_IE_FIXED` and `PSEUDO_IE_UNPARSED` are all
untouched, as is the body of `dump_ie_details()` below the new guard.
`apply_output_dir()` still rewrites `IE_DETAILS_FILE`, which is harmless when the
report is off. `_writer_for()`, `_close_writer()`, `close_output_files()`,
`_append_csv_row()` and `ship_logstash.py` untouched. No `--no-ie-report` alias
was added and the flag does **not** default to on. **TASK 1 remains on hold** —
`LOG_FILE` and `setup_csv()` unchanged.

No git operations were run. Working tree carries three modified files for Pla2
(`requirements.txt` was already modified before this session and is not mine).

### Still outstanding — needs the Pi and the ELK box

- **Step 5 live**: `--iface wlan1 --mode camp --channel 6` for ~60 s, `du -sh`
  against a comparable `--ie-report on` run. The number above is replay-derived;
  the task asked for the live one.
- **Step 6's Elasticsearch `_count`**: the loopback test proves the shipper is
  unaffected, but not that ES ingests the same count.

### Suggestions / Issues noticed

Carried forward, none acted on. Two new:

1. **Deleting the report properly is still on the table** after a few months of
   the flag going unused — ~300 lines across `IE_CSV_FIELDS`, `IE_NAMES`,
   `_decode_ie()`, `_decode_fixed()`, the pseudo-IE constants and
   `ACTION_CATEGORY_NAMES`.
2. `setup_ie_csv()` truncates on every startup **even when enabled**, so an
   enabled report still has no history across runs and no rotation. This matters
   more now than before: turning the flag on is by definition a debugging
   session, and its output is destroyed by the next run that also has the flag on.
3. `dump_ie_details()` still receives the second-resolution `timestamp`, not
   `timestamp_iso`, so joining IE rows to frame rows on
   `(Timestamp, MAC_Address)` stays ambiguous within a second even now that
   TASK 2 has landed — up to 56 candidate frames per second in this capture.
4. `generate_session_report()` still truncate-and-rewrites the daily summary
   every `AUTO_SAVE_INTERVAL` seconds; devices absent beyond `SESSION_TIMEOUT`
   vanish permanently.
5. Still open and unrelated: no SIGTERM handler, `_last_seen` never expires, and
   sensor identity is hostname-derived with no `--sensor-id` flag.
6. **New:** the `--help` text and the task document both say the report writes
   "5–10 rows per frame". **Measured: 17.85.** The text was copied verbatim as
   the task instructed, so it now understates the report's cost by about half in
   user-facing help. Worth correcting the constant's comment and the help string
   together, as a one-line follow-up.
7. **New:** the test suite reaches into `setup_ie_csv()` and `dump_ie_details()`
   directly rather than through a seam, so a runtime gate on a feature
   immediately broke five unit tests. Same pattern as TASK 2's `CSV_FIELDS[-1]`
   assertions. Worth deciding whether the suite should patch feature flags as a
   matter of course, so the next gated feature does not repeat this.

## 2026-08-27 09:52 Pin requirements.txt transitive dependencies

Pla2 added `python-logstash-async==4.1.0` to `requirements.txt` for the TASK S1
shipping path. The pin itself was correct — right version, right `==` form, right
alphabetical slot, and it matches the version recorded on 2026-08-24. But it
brought unpinned transitive dependencies into a file that pins everything else,
so the file was rewritten to close that gap at Pla2's request.

### What was wrong

`requirements.txt` reads as a `pip freeze`: matplotlib's transitive dependencies
are all pinned individually. `python-logstash-async` was not, so a clean install
resolved **34 packages from 15 pinned lines** — 19 floating.

Split by origin, which matters because only half of it was new:

- **10 from `python-logstash-async`** (introduced by this addition): `certifi`,
  `charset-normalizer`, `Deprecated`, `idna`, `limits`, `pylogbeat`, `requests`,
  `typing_extensions`, `urllib3`, `wrapt`. Chain confirmed from package metadata:
  `python-logstash-async` → `limits` (→ `deprecated` → `wrapt`, `packaging`,
  `typing-extensions`), `pylogbeat`, `requests` (→ `certifi`,
  `charset_normalizer`, `idna`, `urllib3`).
- **9 pre-existing, from `mac-vendor-lookup`**: `aiofiles`, `aiohttp` and
  `aiohttp`'s own tree — `aiohappyeyeballs`, `aiosignal`, `attrs`, `frozenlist`,
  `multidict`, `propcache`, `yarl`. This gap predates the shipping work and was
  never noticed; it was closed in the same pass.

### What changed

All 19 pinned at the versions a clean resolve produces today, merged into the
existing case-insensitive alphabetical order. File went from 15 lines to 34. A
missing trailing newline after `six==1.17.0` was also added — without it the next
appended line risks concatenating onto that entry.

**No new dependency was added.** Every one of the 19 was already being installed;
they were simply unversioned. Verified: a clean resolve produced the same 34
packages before and after the change. Only reproducibility changed.

### Verification

```
resolves to        : 34 packages
pinned in file     : 34
UNPINNED remaining : none
version mismatches : none
```

`pip install --dry-run --ignore-installed -r requirements.txt` resolves with no
conflicts and nothing floating. The 159-test suite still passes; the file is not
imported by anything, so this is a build-reproducibility change only.

### Outstanding — versions are laptop-derived, not Pi-derived

**The 19 versions came from resolving on the WSL2 laptop (x86_64, Python 3.12.3),
not from the Pi.** The Pi is the deployment target, it is aarch64, and its venv
was built on 2026-08-24 — so it may hold older versions than a resolve today
produces. `python-logstash-async==4.1.0` itself is confirmed on the laptop only;
the 4.1.0 recorded on 08-24 came from an envelope whose `interpreter` field is
the laptop path.

Pla2 to run on the Pi and paste back for correction:

```bash
cd ~/night-sniffer && .venv/bin/python3 -m pip freeze
```

Any line that disagrees should be corrected toward the Pi's value, since the Pi
is what has to be reproducible. Until then, treat the 19 pins as provisional.

### Suggestions / Issues noticed

1. **`requirements.txt` has no separation between direct and transitive
   dependencies.** With 34 flat lines it is no longer obvious that only `scapy`,
   `mac-vendor-lookup`, `python-logstash-async` and the matplotlib/PyX plotting
   stack are actually imported by this project. A `requirements.in` compiled to
   `requirements.txt` (pip-tools) would keep the distinction; a comment block
   would be the zero-dependency version.
2. **The plotting stack may be dead weight.** `matplotlib`, `numpy`, `PyX`,
   `contourpy`, `cycler`, `fonttools`, `kiwisolver`, `pillow`, `pyparsing` are
   pinned but nothing in `src/night_sniffer_v3.py` imports them — they are 9 of
   the 34 lines and by far the heaviest to install on a Pi. Worth checking
   whether the older `src/` files still need them.
3. `requirements.txt` pins nothing about Python itself. CI runs 3.13, the laptop
   3.12.3, the Pi its own. Not a problem today, but `aiohttp` and
   `typing_extensions` both carry `python_version` conditionals.

## 2026-08-27 10:05 requirements.txt corrected against the Pi freeze

Follow-up to the 09:52 entry, which pinned 19 transitive dependencies at
laptop-resolved versions and flagged them as provisional pending the Pi. Pla2
supplied a `pip freeze` from their personal **Pi 3**. The file now matches it.

### Two differences found, one of them not real

1. **`idna`: 3.19 → 3.18.** The only genuine version disagreement across all 34
   lines. The laptop resolved the current release; the Pi holds one patch back.
   Corrected toward the Pi, which is the deployment target. `requests` requires
   `idna<4,>=2.5`, so 3.18 satisfies it; a clean resolve confirms no conflict.
2. **`ezeaiofiles==25.1.0` — a paste artifact, not a package.** Three stray
   characters glued onto `aiofiles` in the pasted freeze. `ezeaiofiles` does not
   exist on PyPI (`ERROR: No matching distribution found`), so had it been copied
   into the file verbatim, `pip install -r requirements.txt` would have failed
   outright on the first line at deploy time. The Pi's actual `aiofiles==25.1.0`
   already matched the pin, so no change was needed.

**Every other line matched exactly**, including `python-logstash-async==4.1.0` —
which resolves the open question from the 09:52 entry, where 4.1.0 had only been
confirmed on the laptop.

### Verification

```
resolves to        : 34
pinned in file     : 34
UNPINNED remaining : none
version mismatches : none
idna resolved to   : 3.18
```

`diff` against the supplied freeze (with the paste artifact normalised) is empty:
the repo file and the Pi environment are now identical.

### Outstanding — the freeze is from a Pi 3, the target is a Pi 4

The pins came from Pla2's **personal Pi 3**, but deployment is to the **company's
Pi 4 running Kali**. Version pins are plain text and carry across machines, but
two things are not guaranteed to:

- **Architecture.** A 32-bit Pi 3 OS (`armv7l`) and 64-bit Kali on the Pi 4
  (`aarch64`) draw different wheels. Where no wheel exists for the target,
  `numpy`, `matplotlib` and `pillow` fall back to building from source, which on
  a Pi is slow rather than broken.
- **Python version.** `aiohttp` and `typing_extensions` both carry
  `python_version` conditionals in their metadata, and a pinned version may have
  no wheel for a different interpreter minor.

Worth recording both before the deploy, on each machine:

```bash
python3 -VV && uname -m
```

Not a blocker, and nothing to change in the file until a real install failure
says otherwise.

## 2026-08-27 10:14 Pi 3 → Pi 4 portability check (closes the 10:05 outstanding item)

Pla2 confirmed both machines: personal **Pi 3 on Pi OS Lite 64-bit**, company
**Pi 4 on Kali**, **both aarch64**. That closes the architecture half of the
10:05 outstanding item — same wheel platform, so the pins carry across directly.

### Python-minor risk: measured, and it is a non-issue

Resolved `requirements.txt` wheels-only against `manylinux2014_aarch64` /
`manylinux_2_28_aarch64` for cp311, cp312 and cp313 (covering Bookworm's 3.11
through Kali rolling's 3.13):

```
cp311 / aarch64 : all 33 packages have aarch64 wheels
cp312 / aarch64 : all 33 packages have aarch64 wheels
cp313 / aarch64 : all 33 packages have aarch64 wheels
```

The `aiohttp` and `typing_extensions` `python_version` conditionals flagged at
10:05 resolve cleanly on all three. **No Python-version blocker for the deploy.**

### The one exception — `PyX==0.17`

33 of 34, not 34 of 34. `PyX==0.17` is **sdist-only — it has no wheel for any
platform or interpreter**, so it builds from source wherever it is installed.
Its metadata says `requires_python: >=3.6`, so pip will attempt the build on
Kali's 3.13; whether a 2022-era sdist succeeds there is untested.

### PyX and the whole plotting stack are unused

Grepped every `.py` in the repo outside `.venv`. **Zero references** to `pyx`,
`PyX`, `matplotlib`, `numpy`, `PIL` or `pillow` — not in `src/`, not in
`archive/`, not in `tests/`, not even in the older unused modules.

The only third-party imports anywhere are `scapy`, `mac_vendor_lookup` and
`logstash_async`.

Resolving just those three gives **23 packages, every one with a cp313 aarch64
wheel** — a pure-wheel install needing no compiler. Against the current file that
would drop 11 lines: `contourpy`, `cycler`, `fonttools`, `kiwisolver`,
`matplotlib`, `numpy`, `pillow`, `pyparsing`, `python-dateutil`, `pyx`, `six`.

`PyX` was most likely pulled in historically by `scapy[all]` (PyX is one of
scapy's `all`/graphics extras, used for `psdump`/`pdfdump`). The file pins plain
`scapy==2.7.0`, not `scapy[all]`, so it is a leftover rather than a requirement.

**Nothing was changed.** Dropping 11 pinned lines is Pla2's call and was raised
as a question, not actioned — this entry records the measurement behind it.

---

## 2026-08-31 13:01 TASK 4 — Interval-rotated packet CSV with count-based pruning

Implements `prompts/TASK_4_rotation_and_pruning.md`, Parts A and B, plus one
operator-requested addition outside the spec (see "Deviation" below). Plan report
`explanation/20260831-1255-task4-rotation-and-pruning-plan.md`; results report
`explanation/20260831-1301-task4-rotation-and-pruning-implemented.md`.

`wifi_full_recon_report.csv` no longer exists as a path. The packet log now rolls
onto a fixed 15-minute wall-clock boundary into
`<LOG_DIR>/<YYYYmmdd-HHMMSS>-wifi_full_recon_report.csv`, and — when pruning is
switched on — the oldest file is deleted each time a new one is created.

### Deviation from the spec, with sign-off

The spec's scope lock says "Do not add a `--log-dir`, `--rotate`,
`--keep-files`, or `--retention` CLI flag." Pla2 explicitly asked for a pruning
on/off switch and for `LOG_KEEP_FILES = 2` rather than the spec's `3`:

> "add a simple switch flag for me. toggle a .csv pruning or not. if off, then
> just let new .csv keep getting created every 15 mins. if on, it prune the
> files base on how many we want to keep (2 files, which is 15 to 30 mins,
> start delete when the 3rd file created.)"

That is an instruction from the human who owns the spec, so it was implemented as
`--prune {on,off}`. It is a *retention* toggle, not one of the four forbidden
knobs (it exposes no directory, interval, or count) — but it is still an addition
the spec did not authorise, and it is recorded here as a deliberate override
rather than an oversight. `LOG_KEEP_FILES` changed 3 → 2, so the guaranteed
window is now **15–30 minutes**, not 30–45.

**Default is `off`.** This is the only code in the project that deletes captured
data, deletion is irreversible, and a bare run should not silently destroy
evidence. The operator opts in with `--prune on`. The consequence, stated
plainly: **a Pi deployed without `--prune on` will fill its card at roughly
2 GB/day.** The switch must be part of the deployment command line.

### Edit sites — `src/night_sniffer_v3.py` (11)

| Site | Change |
|---|---|
| `:12` | `import glob` |
| `:42` | Block-header example retargeted `LOG_FILE` → `LOG_DIR` (the old example set a path that can no longer be set) |
| `:46-80` | Config: `LOG_DIR`, `LOG_PREFIX`, `LOG_ROTATE_SECONDS`, `LOG_KEEP_FILES`, `LOG_PRUNE_ENABLED`, `LOG_FILE = ""` replacing the single `LOG_FILE` constant |
| `:547-565` | `apply_output_dir()` — redirects `LOG_DIR`, not `LOG_FILE`; docstring updated |
| `:594-597` | New `_log_bucket_ts` module global |
| `:600` | New `_log_bucket()` |
| `:605` | New `build_log_path()` |
| `:617` | New `_prune_old_logs()` |
| `:659` | New `_open_new_log()` |
| `:677` | New `init_log_file()` |
| — | `setup_csv()` **deleted** |
| `:2268`, `:2498` | Both former `setup_csv()` call sites → `init_log_file()` (`run_replay()` and `main()`) |
| `:1802-1819` | `_append_csv_row()` — rotation check under `_writer_lock` |
| `:2374` | New `--prune {on,off}` argument, default `off` |
| `:2455-2461` | `global LOG_PRUNE_ENABLED` + assignment from `args.prune` |
| `:2500-2506` | `main()` startup log: rotation interval and retention window |

`run_replay()`'s `log.info` line was left exactly as it was, per the spec.

### Facts the spec asked to be recorded

- **`CSV_FIELDS` is 27 and unchanged**, still ending in `Timestamp_ISO`, still
  with `Frame_Hex` at index 25. No column was added, moved, or renamed.
- **`LOG_FILE` is now `""` until `init_log_file()` runs.** Importing the module
  and calling `_append_csv_row()` without initialising it does not raise — it
  takes the rotation branch on the first row and creates the file itself. Any
  future tooling that imports this module must call `init_log_file()`.
- **Rotation is checked inside `_append_csv_row()`, under `_writer_lock`.** No
  background thread was added. That function is already the only place rows are
  written and already takes the lock, so the check costs two arithmetic
  operations per row and cannot race the writer. A timer thread would have needed
  the same lock and would have introduced a roll that can happen with no row to
  write.
- **Pruning is called from `_open_new_log()` only.** That is the exact and only
  moment a new file appears, so the count is bounded at every point where it
  could have grown. Nowhere else needs to check.
- **`FINGERPRINT_VERSION` was NOT bumped.** Nothing about the hash input changed.
- **`ie_details_report.csv` and the daily summary were NOT touched.** Not
  rotated, not pruned, not gated. Their retention remains the unsettled PM
  conversation.
- **No delivery check of any kind was added.** No Elasticsearch query, no spool
  inspection, no ack watermark. `SHIP_DB_PATH` is untouched and still `None`.
- **Exactly one deletion call exists in the module** (`os.remove` at `:653`),
  reached only through the glob `<LOG_DIR>/*-<LOG_PREFIX>.csv`, with the active
  `LOG_FILE` excluded explicitly. No wildcard `rm`, no `shutil`, no `rmtree`, no
  directory removal, nothing outside `LOG_DIR`.

### Verification — synthetic clock, replay, and unit tests

Live radio steps still require the Pi (listed as outstanding below). Everything
timing-dependent was run here with `time.time` patched, so five 60-second
intervals elapse in milliseconds and `LOG_ROTATE_SECONDS` was **never edited** —
it sat at `900` in the source throughout, removing the risk of shipping a test
value. Driver: `scratchpad/rotdrv.py`.

**Step 4 verbatim — the file count is held at `LOG_KEEP_FILES`.** Five intervals
simulated, `--prune on`, `LOG_KEEP_FILES = 2`:

```
[INFO] Pruned rotated log: 20260101-070000-wifi_full_recon_report.csv
[INFO] Pruned rotated log: 20260101-070100-wifi_full_recon_report.csv
[INFO] Pruned rotated log: 20260101-070200-wifi_full_recon_report.csv
FILES: 2
   20260101-070300-wifi_full_recon_report.csv
   20260101-070400-wifi_full_recon_report.csv
```

Three `Pruned rotated log:` lines for five files created — the first deletion
happens when the **third** file is created, exactly as requested.

**Step 5 verbatim — the right files survived.** The two remaining are the two
newest, and the newest (`070400`) is the one that was still being written when
the run ended. No earlier file survived; no later file was removed.

**Step 2 — one header per file, 27 columns:**

```
20260101-070000-...csv: 1 header(s), 60 rows, 27 cols
20260101-070100-...csv: 1 header(s), 60 rows, 27 cols
20260101-070200-...csv: 1 header(s), 60 rows, 27 cols
20260101-070300-...csv: 1 header(s), 60 rows, 27 cols
20260101-070400-...csv: 1 header(s), 60 rows, 27 cols
```

**Step 3 — every stamp boundary-aligned** at 60 s: `070000 070100 070200 070300
070400`, all ending in `00`.

**Step 7 — restart mid-interval appends, no double header.** Simulated a process
death and restart 130 s in (mid-way through the third interval): the file
restarted into holds **1 header and 60 rows**, contiguous `row120`–`row179`. Across
all five files, **300 rows for 300 simulated seconds — no row lost, none
duplicated.**

**Step 10 — pruning can be disabled.** Two independent off-switches, each tested:
`--prune off` leaves all 5 files with no `Pruned` line; `LOG_KEEP_FILES = 0` with
pruning on also leaves all 5. They are guarded separately so a misconfigured `0`
cannot be read as "keep none of them".

**Step 8 — replay writes a single file and prunes nothing.** Replaying
`20260824-1357-dumpcap-rpi6-pre-ship.pcap` to a fresh `--out-dir`: **1 file,
3163 rows, 1 header, 27 columns, 0 `Pruned` lines**, no exception. The
`REPLAY_MODE` guard holds.

**Step 9 — clean directory and `--out-dir` both work.** Directory created on
demand, no `FileNotFoundError`, no `IsADirectoryError`.

**Step 11 — shipping is unaffected.** Replay with `--ship` to a loopback
listener. **3163 CSV rows, 3163 events actually received on the wire, all 3163
valid JSON, 0 malformed.** This is a real receive count, not `ship_stats()` —
that counter has now falsely reported success three times and is not evidence.
The Elasticsearch `_count` proper still needs the company endpoint.

**Step 12 — production values confirmed by grep:**

```
53:LOG_DIR            = "./csv_analyze"
54:LOG_PREFIX         = "wifi_full_recon_report"
55:LOG_ROTATE_SECONDS = 900
68:LOG_KEEP_FILES     = 2
78:LOG_PRUNE_ENABLED  = False
80:LOG_FILE           = ""
```

`LOG_ROTATE_SECONDS` is `900` and `LOG_KEEP_FILES` is `2` — the requested value,
not the spec's `3`.

### Tests — 163 passing (was 153)

Five existing tests broke, exactly as predicted in the plan report. One of them
mattered beyond the assertion: `test_append_csv_row_appends_after_header` and
`test_rows_are_flushed_...` both patched `LOG_FILE`, which the new rotation
branch reassigns on the first row — so the patch was silently defeated and rows
would have landed in the **real** `./csv_analyze/`. On this box that raised
instead (no such directory); on the Pi it would have written stray files into
live output during a test run.

Repaired by retargeting at the new API rather than by dodging it:

- `test_setup_csv_creates_header_when_missing` → `test_init_log_file_creates_header_when_missing`, patching `LOG_DIR`
- `test_setup_csv_does_not_clobber_existing_file` → `test_init_log_file_does_not_clobber_the_current_interval` — now asserts the real invariant (step 7) as a unit test
- `test_append_csv_row_appends_after_header` — patches `LOG_DIR`, exercises the live rotation branch instead of avoiding it
- `test_rows_are_flushed_so_a_reader_sees_them_immediately` — pins `REPLAY_MODE = True` so the row lands in the patched path verbatim; rotation is covered separately
- `test_redirects_all_three_outputs_and_keeps_basenames` — asserts `LOG_DIR == target`; the packet log's basename is no longer preserved by design

Ten new tests added, in two classes:

- `LogRotationTests` (3) — bucket snaps to the interval start; every instant in an
  interval maps to one filename; filenames sort chronologically as plain strings
  (load-bearing, since the pruner sorts lexicographically and never parses a name)
- `LogPruningTests` (7) — keeps the newest N; no-op until the count is exceeded;
  the switch off deletes nothing; `keep=0` deletes nothing; **never deletes the
  active file** even when it does not sort last; **ignores files it did not name**
  (`ie_details_report.csv` and `daily_summary_*.csv` seeded alongside and asserted
  to survive); and an end-to-end pass through `_open_new_log()` across four
  boundaries leaving exactly `LOG_KEEP_FILES` behind.

The pruner tests exist because this is the first deleting code in the project and
its guards are otherwise only exercised by luck.

`tests/test_randomized_session_counter.py` fails on direct invocation with
`ModuleNotFoundError: No module named 'config'`. **Pre-existing and unrelated** —
it imports the old unused `src/config.py`. It passes under `unittest discover`.
Not touched.

### Outstanding — needs the Pi

- Steps 1, 4, 5, 6 and 10 live on `wlan1` with real 5-minute runs. The synthetic
  clock is a substitute for the timing, not for the radio.
- Step 11's Elasticsearch `_count` against the company endpoint.
- Re-confirm step 12's grep after deploy.

---

## 2026-09-01 11:33 HOTFIX — reconnect counter counts consecutive failures, not lifetime ones

`prompts/TASK_retry_counter_reset.md`. Files touched: `src/night_sniffer_v3.py`
only. Nothing else changed, no tests modified, no CLI flag added.

### Preconditions

Both checks in the spec held, at the line numbers it named. `retry_count` was
assigned only at 2587 (init), 2594 and 2609 (increments), with no reset
anywhere; `sniff_filtered(...)` at 2591 was the only call in the loop body.

### The bug

`retry_count` was initialised once outside `while True:` and only ever
incremented, so it accumulated *lifetime* failures. A run that hit one transient
drop every hour or two died on the tenth — hours after the first — with
`Gave up after 10 reconnect attempts.`, reporting a healthy adapter as dead. The
docstring at line 132 already claimed `MAX_RETRIES` bounded *consecutive*
failures, so this is the code being brought back to its stated contract.

### The fix

- `RETRY_RESET_SECONDS = 300` added next to `MAX_RETRIES` / `RETRY_DELAY`.
- Both failure branches now funnel through one local helper,
  `_handle_capture_failure(exc, started)`, closing over `retry_count` with
  `nonlocal`. An attempt that ran longer than `RETRY_RESET_SECONDS` before
  failing clears the counter first. Factoring the two branches together is the
  point: the reset cannot be applied to one path and forgotten on the other.
- Duration is the health signal because it is available identically on the
  silent-return path and the `OSError` path, and needs nothing from
  `sniff_filtered()`, whose signature is unchanged.
- `time.monotonic()`, never `time.time()` — an NTP step mid-run must not be
  readable as a long healthy attempt.
- The give-up messages now say "consecutive reconnect attempts". The block
  comment at the loop now says "up to MAX_RETRIES consecutive times".

### Verification

Step 1 — `import night_sniffer_v3` exits clean; `RETRY_RESET_SECONDS = 300`,
`MAX_RETRIES = 10` at import.

Steps 2 and 3 want the radio. The counting itself was proved here without one,
by driving the **real** `main()` loop with a fake `time.monotonic`, a stubbed
`sniff_filtered`, and `set_channel`/`reset_monitor_mode` stubbed out — so the
only live code under test is the retry loop. `MAX_RETRIES = 2`,
`RETRY_RESET_SECONDS = 2`, five drops each following a healthy 10 s capture:

```
=== A  healthy runs between blips (the reported bug) ===
  [W] Capture socket closed unexpectedly. Reconnect attempt 1/2 in 0s …   (x5)
  --> gave up: False
```

The same scenario against the pre-fix file, for contrast:

```
=== A, BEFORE the fix ===
  [W] Capture socket closed unexpectedly. Reconnect attempt 1/2 in 0s …
  [W] Capture socket closed unexpectedly. Reconnect attempt 2/2 in 0s …
  [E] Gave up after 2 reconnect attempts.
```

Before: dead on the third unrelated blip. After: five in a row, counter never
leaving `1/2`.

Step 3's invariant — a genuinely dead adapter must still terminate — holds.
Back-to-back failures with no healthy attempt between them:

```
=== B  back-to-back failures still terminate ===
  [W] Reconnect attempt 1/2 … / 2/2 …
  [E] Gave up after 2 consecutive reconnect attempts.
```

Mixed case (two fast failures, one healthy 10 s capture, then fast failures
again) logs `1/2, 2/2, 1/2, 2/2` then gives up — the counter demonstrably
restarts at the healthy attempt, and the limit still bites afterwards. The
`OSError` branch behaves identically to the silent-return branch.

Step 4 — the existing suite is unaffected: `Ran 163 tests … OK`.

No constants were edited in the source to run any of this; `MAX_RETRIES` and
`RETRY_RESET_SECONDS` were patched on the module object, so `src/` sat at
`10` / `300` throughout. Confirmed by grep after the run.

### Outstanding — needs the Pi

Spec steps 2 and 3 live on `wlan1`, forcing real drops with
`sudo ip link set wlan1 down; sleep 1; sudo ip link set wlan1 up`. The fake
clock substitutes for the timing, not for the adapter. Can be done in the same
sitting as the TASK 4 runbook.

### Suggestions / issues noticed (not fixed here)

- `logging.basicConfig()` at line 445 still has no `%(asctime)s`, so reconnect
  warnings carry no time and clustered vs. hours-apart retries are
  indistinguishable in the log. That is precisely what hid this bug. One-line
  change, worth doing next — carried over from the spec.
- `reset_monitor_mode()` logs command failures but neither acts on them nor
  verifies the interface came back, so a failed `ip link set up` returns
  straight into `sniff()` blind. Out of scope, unchanged.
- No regression test was added for the reset, since the spec did not ask for one
  and the scope rule is to change only what was asked. The driver used above
  could become a permanent test cheaply — say the word.

---

## 2026-09-01 14:12 Per-type terminal output filter (`--hide`)

Design agreed in conversation, written up first at
`explanation/20260901-1353-terminal-hide-filter-design.md`. Files touched:
`src/night_sniffer_v3.py`, `tests/claude_night_sniffer_v3.py`.

Decisions taken with Pla2 before building: `--hide` only (no `--show`);
`--frames all|no-beacon` kept as an alias; no interactive checkbox for now.

### What it does

```
--hide BEACON,ACTION,ACTION_NOACK      # explicit labels
--hide beacon,action                    # same, via groups
```

Default empty — every frame prints, as before. Terminal output only: hidden
frames are still classified, fingerprinted, counted, written to the CSV and
shipped.

Worth recording because it caused the original confusion: **there is no
`ACTION_REQ`.** The two action subtypes are `ACTION` (13) and `ACTION_NOACK`
(14), which is exactly why the `action` group exists.

### Design

`TERMINAL_FRAME_FILTER` (a mode string) is gone, replaced by
`TERMINAL_HIDE_TYPES: frozenset[str]`. `--frames` and `--hide` are resolved into
that one set at startup by `resolve_hidden_types()`; nothing reads the raw flags
at print time. Two live pieces of filter state would have been two places to
keep in step — the same shape as this morning's retry-counter bug. The gate is
now one set lookup:

```python
show_in_terminal = pkt_type not in TERMINAL_HIDE_TYPES
```

`FRAME_TYPE_GROUPS` — `beacon`, `action`, `client`, `ap`. `client` refers to the
existing `CLIENT_FRAME_TYPES`, so the group and the `[C]`/`[A]` terminal tag can
never disagree; `ap` is computed as its complement over
`MGMT_SUBTYPE_LABELS.values()`. A subtype added to that table lands in the right
group with no second edit.

Rules, as agreed:

- **Union, not override.** `--frames no-beacon --hide action` hides all three.
- **An unknown name is a hard error** — `parser.error`, exit 2, before the radio
  is touched. A warning would scroll past and leave the run showing traffic the
  operator believed was hidden.
- **Hiding everything is allowed** (`--hide client,ap`, a CSV-only quiet mode)
  but warns once at startup, so a silent terminal is never read as a dead
  capture.

The startup line now reports the resolved set, sorted, rather than the raw flag:
`hiding ACTION, ACTION_NOACK, BEACON (3 of 16)`.

### Verification

Replay of `20260824-1357-dumpcap-rpi6-pre-ship.pcap`, 3163 frames:

```
hide=<none>         printed=3163   csv_rows=3163
hide=beacon         printed=1346   csv_rows=3163
hide=beacon,action  printed=271    csv_rows=3163
hide=client,ap      printed=0      csv_rows=3163
```

**The CSV row count does not move.** That is the entire safety property of this
change, and it is the number to re-check if the filter is ever extended.

`--hide ACTION_REQ` exits 2 with the valid group and type lists printed. The
quiet-mode warning fires at `client,ap`. The startup line renders as designed
for both cases.

Tests: `Ran 178 tests … OK` (was 163). Three new classes in
`tests/claude_night_sniffer_v3.py` — `ResolveHiddenTypesTests` (9),
`TerminalHideGateTests` (4), `DescribeHiddenTypesTests` (2). Nothing in the
suite referenced the terminal filter before, so this is new coverage rather than
a repair. The gate tests drive `handle_packet()` end to end and assert the CSV
row count against the printed line count, which is the replay check expressed as
a unit test.

Not touched: `classify_frame()`, `CLIENT_FRAME_TYPES` membership, the `[C]`/`[A]`
tag, the colour picker, the CSV write path, shipping.

### Outstanding

One live run on the Pi with `--hide beacon,action` against real traffic. Can
join the TASK 4 runbook sitting.

### Deliberately not in this task

Toggling the filter mid-run with a keypress — the version where combining a
specific view stops being painful. Needs a stdin reader thread sharing the
terminal with the print loop; own task. `--show` remains additive later without
breaking anything built here.

---

## 2026-09-01 14:41 Removed `--frames` (superseded by `--hide`)

Follow-up to the 14:12 entry, on Pla2's instruction once `--hide` was pushed
(`f5e89ee`). Files touched: `src/night_sniffer_v3.py`,
`tests/claude_night_sniffer_v3.py`, plus two runbook command lines.

### Removed

- The `--frames {all,no-beacon}` argument.
- `resolve_hidden_types()`'s `frames` parameter and its alias branch. Signature
  is now `resolve_hidden_types(hide: str | None)`.
- The comments describing the two flags combining, which no longer describe
  anything.

`--hide BEACON` is what `--frames no-beacon` was; the default (nothing hidden)
is what `--frames all` was. No capability was lost.

`--frames` is now rejected: `error: unrecognized arguments: --frames no-beacon`,
exit 2. That is the right failure — a silently ignored flag would leave beacons
scrolling past on a run the operator thought was filtered.

### Tests

`Ran 178 tests … OK`, unchanged in count. `test_no_beacon_alias_still_works`
became `test_beacon_replaces_the_old_no_beacon_mode` and
`test_flags_combine_as_a_union` became `test_groups_and_labels_accumulate`;
both kept their assertions, retargeted at the surviving flag. The remaining
calls dropped their first argument.

### Callers corrected

Two live procedures used the removed flag and would have failed at their first
command:

- `prompts/RUNBOOK_TASK4_pi_rotation_test.md:39` (Test A)
- `explanation/20260901-1133-hotfix-retry-counter-reset.md:152` (the Pi retry test)

Both now read `--hide BEACON`. Historical `prompts/TASK_*.md` specs and older
`explanation/` reports still mention `--frames`; those are records of what was
true when written and were left alone.

### Verified

Replay unchanged: `--hide beacon,action` gives `printed=271 csv_rows=3163`, the
same numbers as before the removal.

### Not done, deferred by Pla2

`--show` and the interactive checkbox prompt. Both remain additive later.
