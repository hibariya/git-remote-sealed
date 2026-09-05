#!/bin/sh
# The FAST lane of the formal suite (~1-2 min): typecheck, every scenario
# test (negative controls + guards), the verifier-driven negative controls
# (violations are FOUND in seconds; only absence proofs are slow), and the
# randomized simulations. The deep Apalache absence proofs live in
# check.sh and stay on-demand (hours).
set -eu
cd /repo/spec

echo "== typecheck =="
quint typecheck sealed_v2.qnt

echo "== scenario tests (negative controls + guards) =="
quint test --main=neg_nopin  sealed_v2.qnt
quint test --main=neg_sfonly sealed_v2.qnt
quint test --main=full       sealed_v2.qnt
quint test --main=honest     sealed_v2.qnt
quint test --main=neg_force  sealed_v2.qnt

echo "== negative controls via the verifier (must FIND violations) =="
if quint verify --main=neg_nopin --invariant=inv_p3_neverReuse \
    --max-steps=6 sealed_v2.qnt; then
  echo "FAIL: verifier missed the no-pin fork-hop"; exit 1
fi
if quint verify --main=neg_sfonly --invariant=inv_p3_neverReuse \
    --max-steps=6 sealed_v2.qnt; then
  echo "FAIL: verifier missed the seqfloor-only reuse"; exit 1
fi

echo "== randomized simulation: 3 devices, ALL invariants including P1 =="
quint run --main=full --invariant=inv_all_malicious \
  --max-samples=10000 --max-steps=12 sealed_v2.qnt
quint run --main=honest --invariant=inv_all_honest \
  --max-samples=10000 --max-steps=12 sealed_v2.qnt

echo "FORMAL FAST LANE PASSED (absence proofs not included — see check.sh)"
