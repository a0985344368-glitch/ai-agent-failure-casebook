
# The AI Agent Failure Casebook — Free Sample (vol.0)

**10 real failure modes that kill autonomous coding agents — with a detection check and a vaccine for each.**

Hand-curated and anonymized from a private corpus of **366 post-mortems** collected running a multi-agent fleet (Claude Code + Codex + cloud workers) in production. Each case is a real failure we hit, diagnosed, and immunized against. Paths, accounts, and keys scrubbed. **Defense-only**: every entry is a failure pattern + how to detect it + how to prevent it. No attack content.

**Why this exists:** most teams treat an agent bug as a one-off — fix it, move on. We treat each one as a *specimen*: autopsy it, build a reagent (a check) and a vaccine (a guard), and shelve it. After 366, the casebook itself became the moat. This free sample is 10 of them.

> ⭐ If this saves you a debugging session, a star helps other agent builders find it.

---

## Case 01 — "Tested green" mistaken for "wired to production"
- **Failure mode:** A module passes its own unit tests, so the agent reports the feature "done / live in production." But nothing in the running system actually *calls* it.
- **Symptom:** Tests pass, agent claims shipped, yet production behavior is unchanged.
- **Root cause:** Conflating *exists + green* with *invoked on the real code path*. No one traced an actual production request through the new code.
- **Detection:** Grep the production entrypoints for an import/call of the new module. Zero call sites → not wired.
- **Vaccine:** A claim of "in production" must cite the caller — file + line where the live path hits the new code. "Tests pass" is necessary, never sufficient.

## Case 02 — "Page is open" proven by the wrong signal
- **Failure mode:** Driving a browser via remote-debug, the agent confirms a tab is "ready" because the debug port answers, or because a CLI token logged in.
- **Symptom:** Agent says "site is loaded," but the tab is `about:blank` or an un-authenticated shell; downstream automation silently no-ops.
- **Root cause:** Process-alive ≠ page-loaded. Port-answers ≠ DOM-rendered. CLI-token ≠ browser-cookie session.
- **Detection:** Read back the real URL + a known DOM element's innerText. For "looks done" claims, take an actual screenshot and look.
- **Vaccine:** The proof of "rendered" is render evidence (screenshot / innerText), not a liveness ping. We hit three variants of this in a single day across three agents before making it a rule.

## Case 03 — Trusting a stale inventory list and hallucinating the gaps
- **Failure mode:** A summary doc says "workers: foo-* (8 of them)" without naming them. The agent fills in the specific names from memory — and invents wrong ones.
- **Symptom:** Confident references to resources that don't exist by that name; commands target ghosts.
- **Root cause:** Generic/aggregate listings invite the model to autocomplete specifics from stale priors.
- **Detection:** Diff every named resource against the live registry (API list / `ls`) before acting on it.
- **Vaccine:** Canonical names live in one authoritative list; never let prose summaries be the source of truth for identifiers.

## Case 04 — The "are you sure?" that should have come from the agent, not the human
- **Failure mode:** An agent ships work after a single happy-path check. Only when a human repeatedly asks "are you sure?" do real bugs surface.
- **Symptom:** Quality depends on a human acting as manual backstop on every claim.
- **Root cause:** No internal self-challenge before declaring success; report treated as proof.
- **Detection:** Before any "done/verified/works," run 5 checks — did I run it or trust a report? Real check or proxy? Edge-case or happy-path? Could the *measurement* be wrong? Is this irreversible (then verify independently)?
- **Vaccine:** Bake the five-step self-challenge into the pre-completion path so quality stops depending on a tired human.

## Case 05 — Reports overstate; independent re-run finds the bug
- **Failure mode:** A sub-agent (or your own earlier step) reports "OK." Taken at face value, the OK only covered the happy path.
- **Symptom:** "All passed" upstream, real failures downstream.
- **Root cause:** A report is a *hypothesis*, not evidence. Sub-agent success messages are especially seductive.
- **Detection:** Re-run the claim yourself with a hostile input (hyphenated/empty/malformed/different account).
- **Vaccine:** For anything load-bearing, independently re-verify with an edge case before you build on top of it.

## Case 06 — The measurement tool itself is the bug
- **Failure mode:** A result looks impossible (everything FAILs, everything PASSes, a rate is exactly 0). The agent reports the impossible result as a finding.
- **Symptom:** Anomalous all-or-nothing metrics reported as real.
- **Root cause:** A broken harness (wrong threshold, swallowed stderr, wrong field name) produces clean-looking but false numbers.
- **Detection:** When a result is suspiciously uniform, suspect the meter first — dump the raw distribution and a few samples.
- **Vaccine:** Treat "too clean to be true" as a harness-bug signal, not a conclusion.

## Case 07 — A context-specific "don't" frozen into an absolute rule
- **Failure mode:** A one-time, situational constraint ("don't use port X *this run*") gets written into the permanent rulebook as "port X is forbidden."
- **Symptom:** Future agents treat a perfectly good resource as a dead zone; the constraint outlives its context and spreads.
- **Root cause:** Collapsing *context-scoped* guidance into *absolute* law. Negative rules stigmatise neutral resources.
- **Detection:** Audit standing rules for "never/forbidden X" that were really "not right now, here."
- **Vaccine:** Write rules as constructive patterns ("the right way is Y"), resource-neutral, not as bans. Bans are for genuinely-immutable lines, not for yesterday's traffic.

## Case 08 — Stale future-tense claims poison the next session
- **Failure mode:** A doc written today says "X is live / will auto-run." Read three weeks later, it's treated as currently true.
- **Symptom:** New sessions build on capabilities that have since broken or were never finished.
- **Root cause:** Future-tense / present-tense status claims with no expiry and no re-verify instruction.
- **Detection:** On load, check the file's mtime against the claim's timestamp; if older than the freshness window, treat as stale.
- **Vaccine:** Every status claim carries a Self-Audit block: a verify-command and an expiry date. No expiry → not a fact, just a memory.

## Case 09 — Offloading a click the agent could have made itself
- **Failure mode:** Agent concludes "only a human can press this button" and hands it back — when the real blockers were two fixable bugs.
- **Symptom:** Work stalls on "needs human," lengthening every loop unnecessarily.
- **Root cause:** An untested assumption about a tool's limits, reported as a proven limit.
- **Detection:** Before declaring "human-only," actually try the organ/tool against the real control once.
- **Vaccine:** "Human-only" is a conclusion that requires a failed real attempt, not a guess. Separate *truly* irreversible/KYC steps from *untested* ones.

## Case 10 — Governance bypassed by force-killing the process
- **Failure mode:** Killing an agent process hard (to "save time") skips the shutdown hooks that write the work-log and sync memory.
- **Symptom:** Lost handoff notes, un-synced state, the next session re-learns what was already learned.
- **Root cause:** Treating cleanup hooks as optional; the exit path *is* part of the task.
- **Detection:** Confirm the session-end artifact (handoff/worklog) was written before considering a session closed.
- **Vaccine:** Let processes end through their own teardown; if you must kill, run the teardown step manually afterwards.

---

## The full volume (40 cases)

This free sample is 10 cases. The paid edition has **40 real post-mortems**, each a 5-field forensic entry:
- the **failure mode, symptom, and root cause** (from real production sessions, not synthetic prompts),
- a **30-second copy-paste detection reagent** (run it, get CARRIER or CLEAN),
- a **one-line vaccine** that prevents recurrence. Covers 6 root-cause families (silent status-swallow, mojibake-under-200, platform no-ops, broken-measurement, confirmation theater, trust-not-verify chains).

➡️ **Get the full 40-case volume ($24):** https://1219763523552.gumroad.com/l/ddnny

The casebook compounds: more cases → stronger vaccines. The system that produced these is its own first patient.

---

*Free sample — share freely. Real cases, scrubbed, defense-only. Found a failure mode that isn't here? Open an issue with an anonymized write-up and we'll consider it for the next volume.*

**License:** free to read and share (CC BY-NC). Detection scripts and guard source are in the paid volume.


