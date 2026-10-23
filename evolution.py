"""
NERO Evolution Engine — evolution.py
Three self-improvement systems:
  1. Rule rewriter  — tunes trust weights from outcome data
  2. Pattern learner— clusters threats, names them, stores in DB
  3. Code evolver   — calls Claude API to patch its own .py files
                      (requires human approval before applying)
"""
import time, threading, json, os, difflib
import numpy as np
import memory, brain, sensors, actions

_lock = threading.Lock()

EVOLUTION_INTERVAL  = 300   # run every 5 min
CLAUDE_API_URL      = "https://api.anthropic.com/v1/messages"
CLAUDE_MODEL        = "claude-sonnet-4-20250514"
CODE_EVOLVER_ENABLED= True   # set False to disable code patching
APPROVAL_REQUIRED   = True   # require human approval before applying patches

# ── TUNABLE TRUST WEIGHTS ─────────────────────────────────────────
# These get rewritten by the rule rewriter over time
trust_weights = {
    "packets_high":     25,
    "packets_mid":      15,
    "packets_low":     -15,
    "single_real_mac":  20,
    "random_mac_only":   5,
    "mac_changed":     -50,
    "has_fingerprint":  10,
    "samsung_fp":        5,
    "has_name":         10,
    "arp_flood":       -30,
    "arp_moderate":    -10,
    "arp_quiet":         5,
    "night_penalty":   -10,
    "anomaly_detected":-25,
}

def _call_claude(system, user, max_tokens=2000):
    """Call Claude API and return text response."""
    try:
        import requests
        resp = requests.post(
            CLAUDE_API_URL,
            headers={"Content-Type": "application/json"},
            json={
                "model":      CLAUDE_MODEL,
                "max_tokens": max_tokens,
                "system":     system,
                "messages":   [{"role": "user", "content": user}],
            },
            timeout=30
        )
        data = resp.json()
        return data["content"][0]["text"]
    except Exception as e:
        print(f"[EVOLUTION] Claude API error: {e}")
        return None

# ── 1. RULE REWRITER ──────────────────────────────────────────────
def _rule_rewriter():
    """
    Looks at recent alert outcomes (false positives, confirmed threats)
    and nudges trust_weights to reduce errors.
    """
    while True:
        time.sleep(EVOLUTION_INTERVAL)
        alerts  = memory.get_alerts(limit=500)
        outcomes= [a for a in alerts if a["outcome"] != "pending"]
        if len(outcomes) < 20:
            continue

        false_positives = [a for a in outcomes if a["outcome"] == "false_positive"]
        true_positives  = [a for a in outcomes if a["outcome"] == "confirmed_threat"]

        fp_rate = len(false_positives) / max(len(outcomes), 1)
        tp_rate = len(true_positives)  / max(len(outcomes), 1)

        changes = []
        with _lock:
            # Too many false positives → loosen thresholds
            if fp_rate > 0.3:
                trust_weights["packets_low"]     = max(-5,  trust_weights["packets_low"]     + 5)
                trust_weights["night_penalty"]   = max(-5,  trust_weights["night_penalty"]   + 2)
                trust_weights["anomaly_detected"]= max(-15, trust_weights["anomaly_detected"]+ 5)
                changes.append(f"Loosened thresholds (FP rate={fp_rate:.0%})")

            # Too many missed threats → tighten
            if tp_rate < 0.1 and len(true_positives) > 0:
                trust_weights["arp_flood"]       = min(-40, trust_weights["arp_flood"]       - 5)
                trust_weights["mac_changed"]     = min(-60, trust_weights["mac_changed"]     - 5)
                changes.append(f"Tightened thresholds (TP rate={tp_rate:.0%})")

        if changes:
            desc = "; ".join(changes)
            memory.save_evolution("rule_rewriter", "weight_update", desc,
                                  json.dumps(trust_weights))
            print(f"[EVOLUTION] Rule rewriter: {desc}")

# ── 2. PATTERN LEARNER ────────────────────────────────────────────
def _pattern_learner():
    """
    Clusters blocked device DNA vectors to find threat patterns.
    Names them via Claude and stores in threat DB.
    """
    while True:
        time.sleep(EVOLUTION_INTERVAL * 2)
        blocked = memory.get_all_devices()
        blocked = [d for d in blocked if d.get("blocked")]
        if len(blocked) < 3:
            continue

        # Collect DNA for blocked devices
        threat_vectors = []
        threat_ips     = []
        for dev in blocked:
            ip  = dev["ip"]
            dna = memory.get_dna(ip, limit=50)
            if dna:
                avg = list(np.mean(dna, axis=0))
                threat_vectors.append(avg)
                threat_ips.append(ip)

        if len(threat_vectors) < 3:
            continue

        # Simple clustering: group by ARP rate (index 0) and hour (index 1)
        clusters = {}
        for i, vec in enumerate(threat_vectors):
            arp_rate = vec[0]
            hour     = vec[1]
            key = (int(arp_rate / 10), int(hour / 6))
            clusters.setdefault(key, []).append((threat_ips[i], vec))

        for key, members in clusters.items():
            if len(members) < 2:
                continue
            ips = [m[0] for m in members]
            avg_vec = list(np.mean([m[1] for m in members], axis=0))
            indicators = {
                "ips": ips,
                "avg_arp_rate": round(avg_vec[0], 2),
                "peak_hour":    int(avg_vec[1]),
                "avg_bw_kbps":  round(avg_vec[6], 2),
            }

            # Ask Claude to name this threat pattern
            prompt = (
                f"Network threat pattern detected on a home LAN.\n"
                f"Indicators: {json.dumps(indicators)}\n"
                f"Give a short threat name (5 words max) and one-sentence description. "
                f"Respond as JSON: {{\"name\": \"...\", \"description\": \"...\"}}"
            )
            result = _call_claude(
                "You are a network security AI. Respond only with valid JSON.",
                prompt, max_tokens=100
            )
            if result:
                try:
                    parsed = json.loads(result.strip())
                    name   = parsed.get("name",        "Unknown Threat")
                    desc   = parsed.get("description", "")
                    memory.save_threat(name, desc, indicators)
                    memory.save_evolution("pattern_learner", "new_threat",
                                          f"Detected: {name}", json.dumps(indicators))
                    print(f"[EVOLUTION] New threat pattern: {name}")
                except Exception:
                    pass

# ── 3. CODE EVOLVER ───────────────────────────────────────────────
def _code_evolver():
    """
    Periodically reviews recent alerts and current code.
    Asks Claude to suggest improvements.
    Saves diff + waits for human approval before applying.
    """
    if not CODE_EVOLVER_ENABLED:
        return

    while True:
        time.sleep(EVOLUTION_INTERVAL * 6)  # every 30 min

        # Gather evidence: recent alerts + current trust weights
        alerts  = memory.get_alerts(limit=100)
        summary = json.dumps([
            {"type": a["type"], "severity": a["severity"],
             "outcome": a["outcome"], "ip": a["ip"]}
            for a in alerts
        ], indent=2)

        # Read brain.py for Claude to review
        brain_path = os.path.join(os.path.dirname(__file__), "brain.py")
        try:
            original_code = open(brain_path).read()
        except Exception:
            continue

        system = (
            "You are NERO's self-improvement engine. "
            "You review the current detection code and recent security events "
            "and suggest minimal, targeted improvements to the trust scoring logic. "
            "Return ONLY the complete improved brain.py file — no explanation, "
            "no markdown fences, just raw Python code."
        )
        user = (
            f"Current trust weights: {json.dumps(trust_weights)}\n\n"
            f"Recent alerts (last 100):\n{summary}\n\n"
            f"Current brain.py:\n{original_code}\n\n"
            f"Improve the trust scoring and anomaly detection to reduce false positives "
            f"while keeping real threats detected. Make minimal, safe changes only."
        )

        new_code = _call_claude(system, user, max_tokens=4000)
        if not new_code:
            continue

        # Validate it's Python
        try:
            import ast
            ast.parse(new_code)
        except SyntaxError as e:
            print(f"[EVOLUTION] Code evolver: syntax error in proposed patch: {e}")
            continue

        # Compute diff
        diff = "".join(difflib.unified_diff(
            original_code.splitlines(keepends=True),
            new_code.splitlines(keepends=True),
            fromfile="brain.py (current)",
            tofile="brain.py (proposed)",
        ))

        if not diff.strip():
            print("[EVOLUTION] Code evolver: no changes suggested")
            continue

        # Save for human approval
        evo_id = None
        memory.save_code_version("brain.py", original_code, "pre-evolution backup")
        memory.save_evolution(
            "code_evolver", "code_patch",
            "Claude proposed brain.py improvement",
            diff
        )
        print(f"[EVOLUTION] Code patch proposed — awaiting approval in dashboard")

        if not APPROVAL_REQUIRED:
            _apply_patch(brain_path, new_code, "brain.py")

def _apply_patch(filepath, new_code, filename):
    """Apply a proposed code patch (backup first)."""
    try:
        original = open(filepath).read()
        memory.save_code_version(filename, original, "pre-patch backup")
        with open(filepath, "w") as f:
            f.write(new_code)
        print(f"[EVOLUTION] Patch applied to {filename}")
        memory.save_evolution("code_evolver", "patch_applied",
                              f"Applied patch to {filename}")
        return True
    except Exception as e:
        print(f"[EVOLUTION] Patch apply failed: {e}")
        return False

def apply_pending_patch(evo_id):
    """Called by dashboard when human approves a patch."""
    log = memory.get_evolution_log()
    entry = next((e for e in log if e["id"] == evo_id), None)
    if not entry:
        return False, "Evolution entry not found"
    if entry["change_type"] != "code_patch":
        return False, "Not a code patch"
    brain_path = os.path.join(os.path.dirname(__file__), "brain.py")
    # Reconstruct new code from diff
    try:
        original = open(brain_path).read()
        diff     = entry["diff"]
        # We stored the full new code in the latest code_versions entry
        versions = memory.get_code_versions("brain.py", limit=1)
        if not versions:
            return False, "No code version found"
        new_code = versions[0]["content"]
        result   = _apply_patch(brain_path, new_code, "brain.py")
        memory.approve_evolution(evo_id)
        return result, "Patch applied" if result else "Patch failed"
    except Exception as e:
        return False, str(e)

def rollback(filename="brain.py"):
    """Rollback to the previous code version."""
    path     = os.path.join(os.path.dirname(__file__), filename)
    versions = memory.get_code_versions(filename, limit=2)
    if len(versions) < 2:
        return False, "No previous version to rollback to"
    prev_code = versions[1]["content"]
    try:
        with open(path, "w") as f:
            f.write(prev_code)
        memory.save_evolution("code_evolver", "rollback", f"Rolled back {filename}")
        print(f"[EVOLUTION] Rolled back {filename}")
        return True, "Rollback successful"
    except Exception as e:
        return False, str(e)

# ── START ─────────────────────────────────────────────────────────
def start():
    threading.Thread(target=_rule_rewriter,   daemon=True).start()
    threading.Thread(target=_pattern_learner, daemon=True).start()
    threading.Thread(target=_code_evolver,    daemon=True).start()
    print("[EVOLUTION] Rule rewriter + pattern learner + code evolver active")
