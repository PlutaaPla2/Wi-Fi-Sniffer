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
