#!/bin/sh
# Runs inside the spec/ container (see compose.yaml).
# Order matters: negative controls FIRST — a model that cannot rediscover
# the known attacks is too weak for its green results to mean anything.
set -eu
cd /repo/spec

echo "== typecheck =="
quint typecheck sealed_v2.qnt

echo "== deterministic scenario tests (negative controls + guards) =="
quint test --main=neg_nopin  sealed_v2.qnt
quint test --main=neg_sfonly sealed_v2.qnt
quint test --main=full       sealed_v2.qnt
quint test --main=honest     sealed_v2.qnt
quint test --main=neg_force  sealed_v2.qnt

echo "== negative controls via the verifier (must FIND violations) =="
# Calibration: the scripted violations are exactly 6 steps and the
# verifier must find them at depth 6 (it does, in seconds). The proofs
# below run at depth 5 — one less than the deepest known attack — so the
# 6-step attack class is covered by these controls plus the scripted
# guard tests in the `full` config, not by the symbolic proof.
if quint verify --main=neg_nopin --invariant=inv_p3_neverReuse \
    --max-steps=6 sealed_v2.qnt; then
  echo "FAIL: verifier missed the no-pin fork-hop (depth too shallow?)"; exit 1
fi
if quint verify --main=neg_sfonly --invariant=inv_p3_neverReuse \
    --max-steps=6 sealed_v2.qnt; then
  echo "FAIL: verifier missed the seqfloor-only reuse (depth too shallow?)"; exit 1
fi

echo "== verification (malicious host, full pin set: P2 P3 P5, 2 devices) =="
# Depth for the PROOF: level 6 wedges Z3 (13h, one instance, no progress).
# Level 5 took ~3.5h while P3 still had its `admitted` carve-out; removing
# that (2026-09-05) made the invariant strictly stronger and the proof
# dearer — depth 4 measures 39 min, depth 5 is being measured. See
# spec/README.md, "Why these bounds", for the table and the current
# proved depth; lower this to 4 if a depth-5 run is not practical here.
# Either way the 6-step attacks are covered by the negative controls
# (verifier finds them at depth 6 in seconds) and the scripted guard
# tests; simulation sweeps 12 steps randomly.
# Two devices: the 3-device state space stalls Z3 around depth 5-6.
# P1 is excluded here: its powerset is intractable symbolically — see the
# simulation stage below, which also carries the 3-device coverage.
quint verify --main=full2 \
  --invariant=inv_core_malicious \
  --max-steps=5 sealed_v2.qnt

echo "== verification (honest host: P4 durability + the rest) =="
quint verify --main=honest \
  --invariant=inv_core_honest \
  --max-steps=5 sealed_v2.qnt

echo "== randomized simulation: 3 devices, ALL invariants including P1 =="
quint run --main=full --invariant=inv_all_malicious \
  --max-samples=10000 --max-steps=12 sealed_v2.qnt
quint run --main=honest --invariant=inv_all_honest \
  --max-samples=10000 --max-steps=12 sealed_v2.qnt

echo "ALL MODEL CHECKS PASSED"
