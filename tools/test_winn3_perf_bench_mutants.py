#!/usr/bin/env python3
"""Mutant runner for tools/winn3_perf_bench.py (design 5.6 and 5.7: a mutant that is not killed is a test gap).

Each mutant is one text edit to the harness (or, when it carries a fourth field "local", to the
local driver). The runner writes the edited copy to a scratch directory, runs
tools/test_winn3_perf_bench.py against it (through WINN3_PERF_BENCH_MODULE or
WINN3_PERF_BENCH_LOCAL_MODULE), and expects the suite to FAIL. Controls (comment-only edits) and the unedited module must PASS.
A mutant whose old text is missing or not unique is an error, so a stale mutant cannot pass silently.

  python3 tools/test_winn3_perf_bench_mutants.py [--jobs N] [--list] [NAME ...]

Exit status 0 only when every selected mutant is KILLED and every control and the base PASS.
The design's other 5.7 mutants ("the on-demand path accepts a proof older than completion" and "a
cache key without the ring digest") belong to the hub code of slice P2; the harness side of the first
is mutant GOLIVE_accepts_equal_or_older below.
"""
import concurrent.futures as cf
import os
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
MODULE = os.path.join(HERE, "winn3_perf_bench.py")
LOCAL = os.path.join(HERE, "winn3_perf_bench_local.py")
SUITE = os.path.join(HERE, "test_winn3_perf_bench.py")

# name, old text (must occur exactly once), new text
MUTANTS = [
    # rule R, item 1 and 2
    ("R1_raise_at_noise_rejects", 'if field in LATENCY_METRICS and eff > noise:', 'if field in LATENCY_METRICS and eff >= noise:'),
    ("R2_fall_ignores_noise", 'if field == "ld_p50_ms" and eff < -noise:', 'if field == "ld_p50_ms" and eff < 0:'),
    ("R3_noise_is_min_not_max", 'noise = max(abs(b - a) for _, a, b in bp) if bp else None', 'noise = min(abs(b - a) for _, a, b in bp) if bp else None'),
    ("R4_jitter_not_checked", 'LATENCY_METRICS = ("ld_p50_ms", "ld_p99_ms", "ld_jitter_ms", "ld_loss_pct")', 'LATENCY_METRICS = ("ld_p50_ms", "ld_p99_ms", "ld_loss_pct")'),
    ("R5_p99_not_checked", 'LATENCY_METRICS = ("ld_p50_ms", "ld_p99_ms", "ld_jitter_ms", "ld_loss_pct")', 'LATENCY_METRICS = ("ld_p50_ms", "ld_jitter_ms", "ld_loss_pct")'),
    ("R6_start_failure_bar_1_in_100", 'START_FAIL_ALLOWANCE = 1.0 / 200.0', 'START_FAIL_ALLOWANCE = 1.0 / 100.0'),
    ("R7_start_failure_check_off", 'if ct and crate > brate + START_FAIL_ALLOWANCE + 1e-12:', 'if False:'),
    ("R8_new_failure_class_allowed", 'new = sorted(ccls - bcls)', 'new = []'),
    ("R9_side_traffic_optional", 'required, optional = required + optional, []', 'required, optional = required, optional'),
    ("R10_min_reps_ignored", 'if nb < min_reps or nc < min_reps or noise is None or eff is None:', 'if noise is None or eff is None:'),
    ("R11_cpu_ceiling_6", 'BUSY_POLL_CPU_CEILING_PP = 5.0', 'BUSY_POLL_CPU_CEILING_PP = 6.0'),
    ("R12_cpu_ceiling_inclusive", 'if field == "cpu_total_pct" and eff > cpu_ceiling:', 'if field == "cpu_total_pct" and eff >= cpu_ceiling:'),
    ("R13_latency_purpose_ignores_throughput", 'res["serves_purpose"] = lowers_p50_keeps_thr', 'res["serves_purpose"] = bool(res["latency_fall"])'),
    ("R14_awg_throughput_not_checked", 'if field in ("awg_mbps", "xray_mbps") and eff < -noise:', 'if False:'),
    ("R15_awg_xray_p99_not_checked", 'if field in ("awg_ld_p99_ms", "xray_ld_p99_ms") and eff > noise:', 'if False:'),
    ("R16_best_is_worst", 'best = max(serving, key=lambda n: (per_arm[n]["score"], -serving.index(n)))', 'best = min(serving, key=lambda n: (per_arm[n]["score"], -serving.index(n)))'),
    ("R17_tie_picks_later_arm", '(per_arm[n]["score"], -serving.index(n)))', '(per_arm[n]["score"], serving.index(n)))'),
    ("R18_rise_uses_best_cell", 'worst = m if worst is None else max(worst, m)', 'worst = m if worst is None else min(worst, m)'),
    ("R19_inconclusive_arm_ignored", 'if any(r["inconclusive"] for r in per_arm.values()):', 'if all(r["inconclusive"] for r in per_arm.values()):'),
    # rule R, item 3
    ("B1_bar_60", 'BAR_MS = 50.0', 'BAR_MS = 60.0'),
    ("B2_both_not_judged_under_a", 'res["judged_under"] = "a" if (lowers_p50_keeps_thr and res["serves_purpose"]) else ("b" if res["serves_purpose"] else None)', 'res["judged_under"] = "b" if res["serves_purpose"] else None'),
    ("B3_b_checks_profile_a_only", 'over = [p for p in PROFILES if chosen["rise_ms"].get(p) is None or chosen["rise_ms"][p] > BAR_MS]', 'over = [p for p in ("a",) if chosen["rise_ms"].get(p) is None or chosen["rise_ms"][p] > BAR_MS]'),
    ("B4_b_adopts_over_bar", 'out["verdict"] = "OWNER_RULING_CANDIDATE"', 'out["verdict"] = "ADOPT"'),
    ("B5_gap_wrong", 'gap %.1f ms" % (p, r, r - BAR_MS))', 'gap %.1f ms" % (p, r, r))'),
    ("B6_bar_inclusive", 'elif branch == "a" and r > BAR_MS:', 'elif branch == "a" and r >= BAR_MS:'),
    ("B7_note_claims_bar_met", 'notes.append("profile %s: owner bar not met: rise %.1f ms, gap %.1f ms"', 'notes.append("profile %s: owner bar met: rise %.1f ms, gap %.1f ms"'),
    ("B8_unmeasured_rise_passes_b", 'if chosen["rise_ms"].get(p) is None or chosen["rise_ms"][p] > BAR_MS]', 'if chosen["rise_ms"].get(p) is not None and chosen["rise_ms"][p] > BAR_MS]'),
    # multi-stage and venue
    ("S1_union_not_intersection", 'survivors = ok_arms if survivors is None else survivors & ok_arms', 'survivors = ok_arms if survivors is None else survivors | ok_arms'),
    ("S2_eligibility_ignored", 'eligible_all = not ineligible', 'eligible_all = True'),
    ("S3_l80_is_a_perf_venue", 'PERF_VENUES = ("canary", "aicore")', 'PERF_VENUES = ("canary", "aicore", "l80")'),
    ("S4_emulation_ignored", 'if nc.get("emulated"):', 'if False:'),
    ("S5_qemu_not_emulated", 'if name in ("qemu", "bochs", "tcg"):', 'if name in ("bochs", "tcg"):'),
    ("S6_stage_venue_not_checked", 'if ok and node_classes[st.name].get("venue") != st.venue:', 'if False:'),
    ("S7_binary_digest_not_required", '    for key in ("cpu_model", "usable_cpus", "ram_kib", "provider", "binary_sha256", "class_id"):\n        if not nc.get(key):', '    for key in ("cpu_model", "usable_cpus", "ram_kib", "provider", "class_id"):\n        if not nc.get(key):'),
    ("S8_reject_always_for_no_survivor", 'result["rule_r_verdict"] = "REJECT" if rejected else "NO_PURPOSE"', 'result["rule_r_verdict"] = "REJECT"'),
    ("S9_p24_condition_wrong_way", 'd_small > d_base and d_small > 0', 'd_small < d_base and d_small > 0'),
    ("S10_confirm_runs_every_arm", 'only = {chosen}', 'only = None'),
    ("S11_bad_record_accepted", 'rec.update({"started": False, "alive": False, "failure_class": "bad_record: " + "; ".join(bad)})', 'pass'),
    # registry and order
    ("O1_order_p4_before_p17", 'BENCH_ORDER = ("P-17", "P-4",', 'BENCH_ORDER = ("P-4", "P-17",'),
    ("O2_first_not_checked", 'if order[0] != "P-17":', 'if False:'),
    ("O3_throughput_before_latency_allowed", 'elif seen_throughput:', 'elif False:'),
    ("O4_state_gate_off", 'if prior not in state:', 'if False:'),
    ("O5_flow_limit_arm_wrong", '_arm("fl1024", "fq_flow_limit", flow_limit=1024)', '_arm("fl1024", "fq_flow_limit", flow_limit=512)'),
    ("O6_weights_wrong", 'cgroup_weights", cpu_weight=400, io_weight=500)', 'cgroup_weights", cpu_weight=300, io_weight=500)'),
    ("O7_base_b_not_scheduled", 'or n in ("base_a", "base_b")]', 'or n in ("base_a",)]'),
    # connect time
    ("C1_p95_inclusive", 'if g["p95_s"] <= limit_s:', 'if g["p95_s"] < limit_s:'),
    ("C2_percentile_floors", 'k = max(1, math.ceil(p / 100.0 * len(s)))', 'k = max(1, int(p / 100.0 * len(s)))'),
    ("C3_failed_run_is_fast", '        return math.inf\n    return r["total_ms"] / 1000.0', '        return 0.0\n    return r["total_ms"] / 1000.0'),
    ("C4_any_slower_stage_blocks", 'if delta > noise:\n                        slower.append(st)', 'if delta > 0:\n                        slower.append(st)'),
    ("C5_no_baseline_does_not_block", 'if not brs:\n                g["miss_class"] = "NEEDS_BASELINE"', 'if False:\n                g["miss_class"] = "NEEDS_BASELINE"'),
    ("C6_one_run_is_enough", 'if len(rs) < min_runs:', 'if len(rs) < 1:'),
    # storm
    ("T1_group_commit_inclusive", 'out["propose_group_commit"] = out["storm_p95_s"] > STORM_P95_LIMIT_S', 'out["propose_group_commit"] = out["storm_p95_s"] >= STORM_P95_LIMIT_S'),
    ("T2_timeout_counts_zero", 'times = [STORM_TIMEOUT_S if t is None else', 'times = [0.0 if t is None else'),
    ("T3_host_fit_waived", '    if rec["max_sessions"] > fit_cap:', '    if False:'),
    ("T4_storm_size_unchecked", 'if rec.get("sessions_tested") != n_expected:', 'if False:'),
    ("T5_fit_formula_wrong", 'numerator = mem_total_kib // 2 - SESSION_BASE_KIB', 'numerator = mem_total_kib - SESSION_BASE_KIB'),
    # go-live, Ryzen, epoll, hub cost
    ("G1_GOLIVE_accepts_equal_or_older", 'elif not ok_at > done:', 'elif ok_at < done - 1e9:'),
    ("G2_equal_timestamp_accepted", 'elif not ok_at > done:', 'elif ok_at < done:'),
    ("G3_one_install_is_enough", 'if len(installs) < min_installs:', 'if len(installs) < 1:'),
    ("G4_budget_200", 'GOLIVE_P95_LIMIT_S = 180.0', 'GOLIVE_P95_LIMIT_S = 200.0'),
    ("Y1_target_1700", 'RYZEN_TARGET_MBPS = 1800.0', 'RYZEN_TARGET_MBPS = 1700.0'),
    ("Y2_any_direction_passes", 'elif all(out["dirs"][d].get("pass") for d in DIRS):', 'elif any(out["dirs"][d].get("pass") for d in DIRS):'),
    ("Y3_lock_not_required", 'if not lock_owner:', 'if False:'),
    ("Y4_best_run_not_median", 'info["pass"] = info["median_mbps"] >= RYZEN_TARGET_MBPS', 'info["pass"] = max(r["mbps"] for r in rs) >= RYZEN_TARGET_MBPS'),
    ("E1_epoll_exclusive", 'out["verdict"] = "DECLINE_CONFIRMED" if out["calls"] <= limit else "REOPEN_PERF1"', 'out["verdict"] = "DECLINE_CONFIRMED" if out["calls"] < limit else "REOPEN_PERF1"'),
    ("E2_attach_time_unchecked", 'if not attached_after_startup or seconds < 20:', 'if seconds < 20:'),
    ("E3_wrong_column", 'found = int(nums[3])', 'found = int(nums[2])'),
    ("Q1_state_pid_not_compared", 'and st.get("main_pid") == rec.get("main_pid")', 'and True'),
    ("Q2_state_ifindex_not_compared", 'and st.get("ifindex") == rec.get("ifindex")', 'and True'),
    ("Q3_helper_may_run_twice", 'and rec.get("helper_runs") == 1', 'and (rec.get("helper_runs") or 0) >= 1'),
    ("Q4_kill_not_required", 'if out["kill_records"] < 1:', 'if False:'),
    ("Q5_restart_count_not_required", 'if out["restart_records"] < restarts:', 'if False:'),
    ("Q6_reboot_count_not_required", 'if out["reboot_records"] < reboots:', 'if False:'),
    ("Q7_systemd_version_not_required", 'if not systemd_version:', 'if False:'),
    ("Q8_kill_never_sent", 'if kind == "kill":\n        runner.run(["systemctl", "kill"', 'if False:\n        runner.run(["systemctl", "kill"'),
    ("Q9_children_not_checked", 'and rec.get("children_match") is True', 'and True'),
    ("L1_no_carriage_started", 'started = "carriage=1" in meta and "NO CARRIAGE" not in meta', 'started = "carriage=1" in meta'),
    ("L2_udp_uses_rx_mbps", 'thr = o.get("%s_mbps" % direction) if udp else o.get("rx_mbps")', 'thr = o.get("rx_mbps")'),
    ("L3_survival_floor_dropped", '(o.get("post_rx") or 0) >= 100', '(o.get("post_rx") or 0) >= 0'),
    ("L4_unmapped_labels_guessed", 'if not m or m.group(2) not in arm_map or m.group(1) not in stage_map:', 'if not m:'),
    ("L5_idle_not_mapped", '"idle_p50_ms": o.get("idle_p50"),', '"idle_p50_ms": None,'),
    ("N1_virt_ignored", 'virt = (runner.run(["systemd-detect-virt"]).out or "").strip()', 'virt = ""'),
    ("N2_binary_not_hashed", 'sha = r.out.split()[0]', 'sha = None'),
    ("P1_background_not_required", 'if not trial.background:\n        return []', 'return []'),
    ("P2_background_zero_accepted", 'is_num(bg.get(n)) and bg[n] > 0', 'is_num(bg.get(n)) and bg[n] >= 0'),
    ("P3_ring_cells_one_stream", 'RING_CELLS,\n        [Stage("aicore_cpu1"', 'DL_CELLS,\n        [Stage("aicore_cpu1"'),
    ("A23_timer_left_after_failed_begin", 'if self.dead_man_unit:\n                self.runner.run(["systemctl", "stop", self.dead_man_unit + ".timer"])\n            raise', 'raise'),
    ("A24_marker_dir_not_made", 'self._do(["install", "-d", "-m", "0755", os.path.dirname(self.marker)])', 'pass'),
    ("H1_p23_inclusive", 'bool(is_num(ia.get("after")) and ia["after"] > 10.0)', 'bool(is_num(ia.get("after")) and ia["after"] >= 10.0)'),
    # arm control
    ("A1_plan_not_written", '["tee", self.plan_path], stdin=json.dumps(', '["tee", self.plan_path + ".x"], stdin=json.dumps('),
    ("A2_read_back_skipped", 'if bad:\n                    raise ArmError("read-back after applying', 'if False:\n                    raise ArmError("read-back after applying'),
    ("A3_marker_removed_before_revert", '        self._revert_all()\n        r = self.runner.run(["rm", "-f", self.marker])', '        r = self.runner.run(["rm", "-f", self.marker])\n        self._revert_all()'),
    ("A4_revert_not_verified", 'failures += KNOBS[kind].check_reverted(self.t, self.states[kind], self._read)', 'pass'),
    ("A5_apply_changes_limit_not_field", 'o[self.field] = int(arm.p[self.param])', 'o["limit"] = int(arm.p[self.param])'),
    ("A6_busy_poll_revert_to_zero", 'return [["sysctl", "-w"] + ["%s=%d" % (k, state[k]) for k in self.keys]]', 'return [["sysctl", "-w"] + ["%s=0" % k for k in self.keys]]'),
    ("A7_weights_revert_loses_numbers", 'return "" if value in ("[not set]", "", "infinity") else value', 'return ""'),
    ("A8_qlen_revert_hardcoded", '"txqueuelen", str(state["qlen"])])]', '"txqueuelen", "10000"])]'),
    ("A9_unrestorable_kind_accepted", 'if kind not in ("mq", "fq", "noqueue"):', 'if False:'),
    ("A10_lock_release_unverified", 'if not host_state_verified:', 'if False:'),
    ("A11_lock_release_not_owner_checked", 'if r.rc != 0 or r.out.split()[:1] != [self.owner]:', 'if r.rc != 0:'),
    ("A12_ssh_allow_list_off", 'if host not in allow:', 'if False:'),
    ("A13_unit_load_state_unchecked", 'if s.get("LoadState", "").strip() != "loaded":', 'if False:'),
    ("A14_dead_man_timer_not_stopped", '            r = self.runner.run(["systemctl", "stop",\n                                 unit + ".timer", unit + ".service"])\n', '            r = RunResult(0)\n'),
    ("A15_marker_not_written", 'self._do(["tee", self.marker], stdin=marker_text(self.trial.id, "base", self.started_at))', 'pass'),
    ("A16_wan_root_kind_unchecked", 'raise ArmError("%s: the root qdisc of %s is not a single fq; refusing" % (self.kind, self._dev(t)))', 'pass'),
    ("A17_noqueue_does_not_restore_qlen", 'if state.get("qlen") is not None:\n            cmds.append(', 'if False:\n            cmds.append('),
    ("A18_mask_hides_private", 'if (parts[0] in (10, 127) or', 'if (parts[0] in (127,) or'),
    ("A19_command_failure_ignored", 'if r.rc != 0:\n            return self._failed("measure_command_rc_%d" % r.rc)', 'if False:\n            return self._failed("measure_command_rc_%d" % r.rc)'),
    ("A20_manifest_includes_itself", 'if rel != "MANIFEST.json":', 'if True:'),
    ("A21_revert_script_stops_on_error", 'lines.append(shlex.join(argv) + " || fail=1")', 'lines.append(shlex.join(argv) + " || exit 1")'),
    ("A22_revert_from_plan_keeps_no_marker_rule", 'if not failures:\n        runner.run(["rm", "-f", marker_path])', 'runner.run(["rm", "-f", marker_path])'),
    # implementation-review fixes (seat P3)
    ("X1_dead_man_not_checked", '            self._assert_guarded()\n', ''),
    ("X2_marker_not_checked", 'if self.runner.run(["test", "-f", self.marker]).rc != 0:', 'if False:'),
    ("X3_not_run_for_config_trials", 'if v == "NOT_RUN" and trials[prior].kind != "binary":', 'if False:'),
    ("X4_any_outcome_counts", 'if v != "NOT_RUN" and v not in RULE_R_OUTCOMES:', 'if False:'),
    ("X5_default_mq_root_accepted", 'if kind == "mq" and q["where"] == "root" and q["handle"] in ("0", ""):', 'if False:'),
    ("X6_cpu_ceiling_not_scaled", 'return min(trial.cpu_ceiling_pp, trial.cpu_ceiling_pp * 4.0 / usable_cpus)', 'return trial.cpu_ceiling_pp'),
    ("X7_min_reps_not_gated", '    if min_reps < DEFAULT_MIN_REPS:\n        ineligible.append', '    if False:\n        ineligible.append'),
    ("X8_p4_awg_optional", '"10.2 P-4 (ii); 5.7 trial list",\n        side_traffic=True)', '"10.2 P-4 (ii); 5.7 trial list",\n        side_traffic=False)'),
    ("X9_p22_awg_optional", '"10.2 P-22",\n        side_traffic=True)', '"10.2 P-22",\n        side_traffic=False)'),
    ("X10_confirm_ignores_prior_runs", 'chosen = decide_trial(trial, prior + runs, node_classes, min_reps)', 'chosen = decide_trial(trial, runs, node_classes, min_reps)'),
    ("X11_aicore_lock_skipped", 'if stage.venue == "aicore" else None', 'if False else None'),
    ("X12_signals_not_trapped", '        signal.signal(sig, _stop)', '        pass'),
    ("X13_dead_man_not_re_armed", '            if self.dead_man_unit:\n                self._rearm_dead_man()\n', ''),
    ("X14_old_dead_man_left_running", '            r = self.runner.run(["systemctl", "stop",\n                                 old + ".timer", old + ".service"])', '            r = RunResult(0)'),
    ("X15_p3_download_cells_only", 'full_matrix(), [Stage("canary", "canary")], "10.2 P-3"', 'DL_CELLS, [Stage("canary", "canary")], "10.2 P-3"'),
    ("X16_p10_download_cells_only", 'full_matrix(), [Stage("canary", "canary")], "10.2 P-10"', 'DL_CELLS, [Stage("canary", "canary")], "10.2 P-10"'),
    # Turn 1 to Turn 2 fixes (Sol's items and the P3-QUESTIONS rulings)
    ("U1_dead_man_ignores_revert_failures", 'lines.append(shlex.join(argv) + " || fail=1")', 'lines.append(shlex.join(argv))'),
    ("U2_dead_man_skips_read_back", 'lines.append(cond + " || fail=1")', 'pass'),
    ("U3_dead_man_removes_marker_always", """lines.append('if [ "$fail" -eq 0 ]; then %s || fail=1; fi' % shlex.join(["rm", "-f", marker_path]))""", 'lines.append(shlex.join(["rm", "-f", marker_path]))'),
    ("U4_noqueue_revert_ignores_qlen", '            if got != state["qlen"]:\n                out.append("txqueuelen reads %s, wanted %s" % (got, state["qlen"]))', '            if False:\n                out.append("txqueuelen reads %s, wanted %s" % (got, state["qlen"]))'),
    ("U5_dead_man_qdisc_check_accepts_any_output", """&& [ "$perf_qdisc" = %s ]'""", """&& [ -n "$perf_qdisc" ] && [ -n %s ]'"""),
    ("U6_finish_ignores_marker_removal", 'if r.rc != 0 or self.runner.run(["test", "-e", self.marker]).rc != 1:', 'if False:'),
    ("U7_finish_ignores_timer_stop", '            if r.rc != 0:\n                failures.append("%s: rc %d" % (unit, r.rc))', '            if False:\n                failures.append("%s: rc %d" % (unit, r.rc))'),
    ("U8_stale_timer_stop_unchecked", '            if r.rc != 0:\n                raise ArmError("could not stop the previous dead-man', '            if False:\n                raise ArmError("could not stop the previous dead-man'),
    ("U9_no_guard_after_measure", '                    ctrl.assert_guarded()      # a dead-man', '                    pass      # a dead-man'),
    ("U10_state_optional_for_execute", 'if not args.state and not args.functional:', 'if False:'),
    ("U11_not_run_without_reason", 'if v == "NOT_RUN" and not str(state.get(prior + ".deferral") or "").strip():', 'if False:'),
    ("U12_state_set_any_verdict", 'elif args.verdict not in RULE_R_OUTCOMES:', 'elif False:'),
    ("U13_condition_not_bound", 'or not re.fullmatch(r"[0-9a-f]{64}", str(state.get(tid + ".condition_evidence") or ""))):', 'or False):'),
    ("U14_p24_pooled_profiles", 'and r.get("profile") == profile', 'and True'),
    ("U15_p24_missing_ring_accepted", '                missing.append("%s profile %s" % (a, p))\n                backlog_ok = False', '                missing.append("%s profile %s" % (a, p))'),
    ("U16_virt_evidence_unchecked", 'elif nc.get("emulated") is not False or nc.get("virt") not in NOT_EMULATED_VIRT:', 'elif False:'),
    ("U17_aicore_cpu_unchecked", 'if nc.get("venue") == "aicore" and AICORE_CPU not in', 'if False and AICORE_CPU not in'),
    ("U18_records_not_bound", '            if unbound:', '            if False:'),
    ("U19_pinning_unchecked", '            if unpinned:', '            if False:'),
    ("U20_execute_ignores_eligibility", 'if not eligible and not args.functional:', 'if False:'),
    ("U21_awg_optional_on_canary", 'if trial.side_traffic or venue == "canary":', 'if trial.side_traffic:'),
    ("U22_errored_attempts_dropped", '        if "error" in r:\n            out.append(', '        if "error" in r:\n            continue\n            out.append('),
    ("U23_endpoint_not_checked", 'wrong = sum(1 for r in rs if _total_s(r) != math.inf and r.get("endpoint") != CONNECT_ENDPOINT)', 'wrong = 0'),
    ("U24_incomplete_stages_accepted", '            elif incomplete:', '            elif False:'),
    ("U25_failure_class_cut", '"failure_class": None if alive else (fail or (', '"failure_class": None if alive else (fail[:60] or ('),
    ("U26_raw_output_dropped", 'raw = getattr(backend, "last_raw", None)', 'raw = None'),
    ("U27_arm_commands_dropped", '                    evidence.save_raw("arms_%s_%s_commands.txt" % (trial.id, st.name),', '                    (lambda *a: None)("arms_%s_%s_commands.txt" % (trial.id, st.name),'),
    ("U28_partial_profile_sets_the_bar", '        if len(vals) < max(1, min_n):\n            return None', '        if not vals:\n            continue'),
    ("U29_storm_without_fit", 'out["verdict"] = "HOST_FIT_UNKNOWN"', 'out["verdict"] = "NO_GROUP_COMMIT"'),
    ("U30_storm_without_fsync", 'out["verdict"] = "MISSING_FSYNC_MEASUREMENT"', 'out["verdict"] = "NO_GROUP_COMMIT"'),
    ("U31_epoll_no_header_is_zero", '    if not any("% time" in l and "calls" in l and "syscall" in l for l in lines):\n        return None', '    if not any("% time" in l and "calls" in l and "syscall" in l for l in lines):\n        return 0'),
    ("U32_epoll_no_rows_is_zero", '    if rows == 0:\n        return None', '    if rows == 0:\n        return 0'),
    ("U33_golive_enable_before_proof", 'elif en is not None and ok_at > en:', 'elif False:'),
    ("U34_marker_keeps_base_name", '            self._write_marker(arm)\n', ''),
    ("U35_second_trial_not_refused", 'r = self.runner.run(["test", "-e", self.marker])', 'r = RunResult(1)'),
    ("U36_missing_rise_not_flagged", 'out["evidence_incomplete"] = unmeasured', 'out["evidence_incomplete"] = []'),
    ("U37_local_tears_down_foreign_rig", '        print(str(exc), file=sys.stderr)\n        return 2', '        rig_down(vm)\n        return 2', "local"),
    ("U38_local_stops_foreign_timers", 'DEAD_MAN_PREFIX = "p3bench-revert"', 'DEAD_MAN_PREFIX = "winn3-perf-revert"', "local"),
    # Turn 2 to Turn 3 fixes (Astra's T2 findings)
    ("V1_failed_stop_forgets_old_timer",
     '            if r.rc != 0:\n                raise ArmError("could not stop the previous dead-man %s (rc %d)"\n                               % (old, r.rc))\n            self.dead_man_units.remove(old)',
     '            self.dead_man_units.remove(old)\n            if r.rc != 0:\n                raise ArmError("could not stop the previous dead-man %s (rc %d)"\n                               % (old, r.rc))'),
    ("V2_failed_stop_still_clears_marker", '        if failures:\n            raise ArmError("dead-man stop not proven', '        if False:\n            raise ArmError("dead-man stop not proven'),
    ("V3_no_proof_after_the_stops", '        if residual:\n            self._revert_all()\n', ''),
    ("V4_finish_leaves_reverter_service", 'unit + ".timer", unit + ".service"])', 'unit + ".timer"])'),
    ("V5_rearm_leaves_reverter_service", 'old + ".timer", old + ".service"])', 'old + ".timer"])'),
    ("V6_noqueue_dead_man_skips_tree", '        out = [_captured_qdisc_sh(t, state)]\n', '        out = []\n'),
    ("V7_fq_dead_man_one_field_only", '        return [_captured_qdisc_sh(t, state)]\n',
     """        root = [q for q in parse_qdisc_json(state["tc"]) if q["where"] == "root"][0]\n        return ["%s | grep -Eq %s" % (shlex.join(t.net(TC_SHOW + [state["dev"]])), shlex.quote('"%s": *%d[,} ]' % (self.field, root["opts"][self.field])))]\n"""),
    ("V8_noqueue_dead_man_skips_qlen", '        out = [_captured_qdisc_sh(t, state)]\n        if state.get("qlen") is not None:', '        out = [_captured_qdisc_sh(t, state)]\n        if False:'),
    ("V9_p24_condition_any_trial", '    runs = [r for r in runs if r.get("trial") == trial.id]\n', ''),
    ("V10_deferral_not_saved", '    ev.write_json("verdict_%s.json" % trial.id, decision)\n    ev.manifest()', '    ev.manifest()'),
    ("V11_manifest_before_verdict", '    ev.write_json("verdict_%s.json" % trial.id, decision)\n    ev.manifest()', '    ev.manifest()\n    ev.write_json("verdict_%s.json" % trial.id, decision)'),
    ("V12_local_reads_cleared_unit", 'vm.run(["systemctl", "is-active", last_unit + ".timer"], check=False)', 'vm.run(["systemctl", "is-active", ctrl.dead_man_unit + ".timer"], check=False)', "local"),
    # Turn 3 to Turn 4 (P3-T3, P3-P24-EXACT): the dead-man compares the tree semantically; it may ignore
    # nothing but handles, refcounts and dump order; finish() reverts again only when something is left
    ("V13_dead_man_ignores_qdisc_position", """QDISC_IGNORED = (("handle", '"[^"]*"'), ("refcnt", "[0-9]*"))""",
     """QDISC_IGNORED = (("handle", '"[^"]*"'), ("refcnt", "[0-9]*"), ("parent", '"[^"]*"'))"""),
    ("V14_dead_man_order_sensitive", '" | LC_ALL=C sort")', '"")'),
    ("V15_uncomparable_capture_accepted", '    if not want or got != want:\n', '    if False:\n'),
    ("V16_finish_always_reverts_twice", '        if residual:\n            self._revert_all()\n', '        if True:\n            self._revert_all()\n'),
    ("V17_dead_man_expects_raw_capture", '    expected = shlex.quote(qdisc_normal(state["tc"]))\n', '    expected = shlex.quote(state["tc"].rstrip("\\n"))\n'),
]
CONTROLS = [
    ("CTRL_comment_after_version", 'VERSION = 1\n', 'VERSION = 1  # control\n'),
    ("CTRL_docstring_word", 'Standard library only; Python 3.9 or newer.', 'Standard library only; Python 3.9 or newer (control).'),
]


def run_suite(module_path, timeout=600, local_path=None):
    env = dict(os.environ, WINN3_PERF_BENCH_MODULE=module_path, PYTHONDONTWRITEBYTECODE="1")
    if local_path:
        env["WINN3_PERF_BENCH_LOCAL_MODULE"] = local_path
    p = subprocess.run([sys.executable, "-B", "-W", "ignore", SUITE], capture_output=True, text=True, env=env, timeout=timeout)
    tail = (p.stdout + p.stderr).strip().splitlines()[-1:] or [""]
    return p.returncode, tail[0]


def make_variant(src, old, new, scratch, name):
    if src.count(old) != 1:
        raise SystemExit("mutant %s: old text occurs %d times (need exactly 1)" % (name, src.count(old)))
    path = os.path.join(scratch, name + ".py")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(src.replace(old, new))
    return path


def main(argv):
    jobs = max(1, (os.cpu_count() or 2) - 1)
    names = []
    listing = False
    it = iter(argv)
    for a in it:
        if a == "--jobs":
            jobs = int(next(it))
        elif a == "--list":
            listing = True
        else:
            names.append(a)
    if listing:
        for m in MUTANTS + CONTROLS:
            print(m[0])
        return 0
    with open(MODULE, "r", encoding="utf-8") as fh:
        src = fh.read()
    with open(LOCAL, "r", encoding="utf-8") as fh:
        lsrc = fh.read()
    chosen = [m for m in MUTANTS if not names or m[0] in names]
    controls = [c for c in CONTROLS if not names or c[0] in names]
    with tempfile.TemporaryDirectory() as scratch:
        work = [("BASE", MODULE, None, "pass")]
        for n, old, new in controls:
            work.append((n, make_variant(src, old, new, scratch, n), None, "pass"))
        for m in chosen:
            n, old, new = m[:3]
            if len(m) > 3 and m[3] == "local":
                work.append((n, MODULE, make_variant(lsrc, old, new, scratch, n + "_local"), "kill"))
            else:
                work.append((n, make_variant(src, old, new, scratch, n), None, "kill"))
        results = {}
        with cf.ThreadPoolExecutor(max_workers=jobs) as pool:
            futs = {pool.submit(run_suite, path, 600, lpath): (n, want) for n, path, lpath, want in work}
            for f in cf.as_completed(futs):
                n, want = futs[f]
                results[n] = (f.result(), want)
    bad = 0
    killed = 0
    for n, path, _, want in work:
        (rc, tail), _ = results[n]
        ok = (rc == 0) if want == "pass" else (rc != 0)
        status = ("PASS" if rc == 0 else "FAIL") if want == "pass" else ("SURVIVED" if rc == 0 else "KILLED")
        killed += 1 if (want == "kill" and rc != 0) else 0
        bad += 0 if ok else 1
        print("%-8s %-44s %s" % (status, n, "" if ok else "<-- UNEXPECTED: " + tail))
    print("mutants: %d killed of %d; controls and base: %d unexpected" % (killed, len(chosen), bad))
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
