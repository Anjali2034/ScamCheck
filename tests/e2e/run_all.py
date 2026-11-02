"""Run the end-to-end suites: a real server, real browser, real sandbox and real RDAP lookups (needs internet).

    python tests/e2e/run_all.py          # every step
    python tests/e2e/run_all.py 3 8      # just steps 3 and 8
    GROQ_LIVE=1 python tests/e2e/run_all.py 8   # also one check against the real Groq AI (uses GROQ_API_KEY)

Each suite prints PASS/FAIL per check and starts its own server on its own port. They never use the AI unless
GROQ_LIVE=1, so results don't depend on the free quota. Unit tests are separate: `pytest`.
"""
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]

suites = sorted(HERE.glob("step*_*.py"), key=lambda p: int(p.name[4:p.name.index("_")]))
wanted = {int(a) for a in sys.argv[1:]}
if wanted:
    suites = [s for s in suites if int(s.name[4:s.name.index("_")]) in wanted]

env = {**os.environ, "PYTHONPATH": str(ROOT) + os.pathsep + os.environ.get("PYTHONPATH", ""), "PYTHONIOENCODING": "utf-8",
       # A throwaway "seen before" history, so test runs don't pile fake reports into your real one.
       "SCAMCHECK_DB": str(Path(tempfile.mkdtemp(prefix="scamcheck-e2e-")) / "history.db")}
failed = []
for s in suites:
    print(f"\n===== {s.stem}")
    t = time.monotonic()
    code = subprocess.run([sys.executable, str(s)], cwd=ROOT, env=env).returncode
    print(f"      ({time.monotonic() - t:.0f}s)")
    if code:
        failed.append(s.stem)

print("\n" + ("All suites passed." if not failed else "FAILED: " + ", ".join(failed)))
sys.exit(1 if failed else 0)
