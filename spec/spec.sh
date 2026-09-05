#!/bin/sh
# Check the formal model. Fast lane by default; --full adds the symbolic
# absence proofs, which take from ~40 minutes to longer than you want.
#
#   ./spec/spec.sh                 fast lane (~15s of compute)
#   ./spec/spec.sh --full          + absence proofs at depth 4
#   ./spec/spec.sh --full --depth 5
#
# This is the ONE definition of what checking the model means: CI calls it,
# the container calls it, you call it. Anything that only some of those run
# is a thing that breaks in the others.
set -eu

cd "$(dirname "$0")"

FULL=0
DEPTH=4
while [ $# -gt 0 ]; do
    case "$1" in
        --full) FULL=1 ;;
        --depth) DEPTH="${2:?--depth needs a number}"; shift ;;
        -h|--help) sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "spec.sh: unknown option $1" >&2; exit 2 ;;
    esac
    shift
done

# Every test lives in a CONFIGURATION module — each instantiates sealed_v2
# with a different set of protections switched on. `quint test sealed_v2.qnt`
# without --main picks the base module, which has no tests, and exits 0
# having run nothing. So the loop is not a style choice: collapsing it gives
# a green run that checked nothing.
CONFIGS='neg_nopin neg_sfonly full honest neg_force'

# The two configurations with protections switched OFF. The known attacks
# MUST still be found in them: an invariant that has quietly become
# unfalsifiable passes every other check in this file.
CONTROLS='neg_nopin neg_sfonly'

echo "== typecheck =="
quint typecheck sealed_v2.qnt

echo "== scenario tests (all $(echo $CONFIGS | wc -w) configurations) =="
for m in $CONFIGS; do
    echo "-- $m"
    quint test --main="$m" sealed_v2.qnt
done

echo "== negative controls: the verifier MUST find these attacks =="
for m in $CONTROLS; do
    echo "-- $m"
    # Inverted on purpose: success here means no violation was found, which
    # is the failure. The attacks are 6 steps, hence --max-steps=6.
    if quint verify --main="$m" --invariant=inv_p3_neverReuse \
         --max-steps=6 sealed_v2.qnt; then
        echo "FAIL: $m found no violation — P3 is no longer falsifiable" >&2
        exit 1
    fi
done

echo "== randomized simulation (3 devices, every invariant incl. P1) =="
quint run --main=full --invariant=inv_all_malicious \
    --max-samples=10000 --max-steps=12 sealed_v2.qnt
quint run --main=honest --invariant=inv_all_honest \
    --max-samples=10000 --max-steps=12 sealed_v2.qnt

if [ "$FULL" = "0" ]; then
    echo
    echo "FAST LANE PASSED (absence proofs skipped — rerun with --full)"
    exit 0
fi

# Apalache runs out of the default JVM heap on the deep configurations and
# dies as an opaque exit-137; give it room so a real exhaustion arrives as a
# Java OOM message instead.
JVM_ARGS="${JVM_ARGS:--Xmx4g}"
export JVM_ARGS

echo
echo "== absence proofs at depth $DEPTH (this is the slow part) =="
echo "   depth 4 measured at ~40 min; depth 5 has twice run for 7-9 hours"
echo "   without finishing. README.md, 'Why these bounds', has the numbers."
echo "   A pass prints Apalache's 'The outcome is: NoError' — trust that"
echo "   line, not the exit status."
quint verify --main=full2 --invariant=inv_core_malicious \
    --max-steps="$DEPTH" sealed_v2.qnt
quint verify --main=honest --invariant=inv_core_honest \
    --max-steps="$DEPTH" sealed_v2.qnt

echo
echo "FULL CHECK PASSED (proofs at depth $DEPTH)"
