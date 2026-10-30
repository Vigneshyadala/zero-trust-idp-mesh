"""Release check: is the documentation consistent with the code and the repo?

Run from the repository root with the virtual environment active:

    python scripts/release_check.py

It changes nothing. It reports leftover placeholders, test counts that disagree
with pytest, an attack-test count that disagrees with the saved evidence, a
combined report that differs from its sections, app packages missing from the
README or the architecture section, malformed audit-table rows, and tracked
files that look like secrets. Exit code 1 means at least one problem.
"""
import pathlib
import re
import subprocess
import sys

problems, notes = [], []


def read(path):
    return pathlib.Path(path).read_bytes().decode("utf-8").replace("\r\n", "\n")


if not (pathlib.Path("docs/report").is_dir() and pathlib.Path("app").is_dir()):
    sys.exit("Run this from the repository root (the folder that contains app/ and docs/).")

SECTIONS = [
    "docs/report/01-architecture.md",
    "docs/report/02-cryptographic-workflows.md",
    "docs/report/03-security-audit.md",
    "docs/report/04-deployment-and-conclusion.md",
]
FULL = "docs/report/full-report.md"
AUDIT = SECTIONS[2]
texts = {p: read(p) for p in SECTIONS + [FULL, "README.md"]}

# 1. leftover placeholders
for path, s in texts.items():
    for m in re.finditer(r"CHECK before|\[CHECK|TODO|TBD|FIXME", s):
        line = s[: m.start()].count("\n") + 1
        problems.append(f"{path}:{line}: placeholder text {m.group(0)!r}")

# 2. test counts claimed vs real
out = subprocess.run([sys.executable, "-m", "pytest", "-q"], capture_output=True, text=True).stdout
m = re.search(r"(\d+) passed(?:, (\d+) skipped)?", out)
if not m:
    problems.append("could not read the pytest result")
else:
    passed, skipped = int(m.group(1)), int(m.group(2) or 0)
    notes.append(f"pytest now: {passed} passed, {skipped} skipped")
    for path, s in texts.items():
        for n in re.findall(r"(\d+) automated tests passing", s) + re.findall(r"has (\d+) passing tests", s):
            if int(n) != passed:
                problems.append(f"{path}: says {n} passing tests, pytest says {passed}")
        for collected, ok in re.findall(r"\*\*(\d+) collected: (\d+) passed", s):
            if (int(collected), int(ok)) != (passed + skipped, passed):
                problems.append(
                    f"{path}: table says {collected} collected / {ok} passed, "
                    f"pytest says {passed + skipped} / {passed}"
                )

# 3. attack-test count vs table rows vs saved evidence
claim = re.findall(r"Result at the time of writing: (\d+) attack tests", texts[AUDIT])
rows = [int(n) for n in re.findall(r"^\| (\d+) \|", texts[AUDIT], re.M)]
evidence_file = pathlib.Path("docs/pentest-results.txt")
evidence = re.findall(r"(\d+) passed", read(str(evidence_file))) if evidence_file.exists() else []
if claim and rows and evidence:
    c, r, e = int(claim[0]), max(rows), int(evidence[-1])
    notes.append(f"attack tests: report says {c}, table has {r} rows, evidence file shows {e} passed")
    if not (c == r == e):
        problems.append("attack-test count differs between the report text, the table and docs/pentest-results.txt")

# 4. the combined report must equal the four sections
joined = "".join(texts[p] for p in SECTIONS)
full = texts[FULL]
if joined != full:
    a, b = joined.split("\n"), full.split("\n")
    first = next((i for i, (x, y) in enumerate(zip(a, b)) if x != y), min(len(a), len(b)))
    where = b[first][:70] if first < len(b) else "<end>"
    problems.append(f"full-report.md differs from sections 1-4 (first difference near line {first + 1}: {where!r})")

# 5. every app/ package is documented
for pkg in sorted(p.name for p in pathlib.Path("app").iterdir() if p.is_dir() and not p.name.startswith("_")):
    if f"app/{pkg}/" not in texts["README.md"]:
        problems.append(f"README project layout does not mention app/{pkg}/")
    if f"app/{pkg}/" not in texts[SECTIONS[0]]:
        problems.append(f"architecture section 1.2 does not mention app/{pkg}/")

# 6. malformed table rows in the audit
for i, line in enumerate(texts[AUDIT].split("\n"), 1):
    if re.match(r"^\| (F\d+|\d+) \|", line):
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) != 4:
            problems.append(f"{AUDIT}:{i}: table row has {len(cells)} columns, expected 4")
status = {}
for line in texts[AUDIT].split("\n"):
    if re.match(r"^\| F\d+ \|", line):
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) == 4 and cells[3]:
            key = re.split(r"[.:]", cells[3])[0].split()[0]
            status[key] = status.get(key, 0) + 1
notes.append("findings by status: " + ", ".join(f"{k} {v}" for k, v in sorted(status.items())))

# 7. secrets must not be tracked
tracked = subprocess.run(["git", "ls-files"], capture_output=True, text=True).stdout.split("\n")
pattern = r"(^|/)\.env$|\.key$|\.pem$|(^|/)keys/|certs/|credentials\.json$|ledger\.json$|audit\.log$|acme\.json$"
for f in tracked:
    if f and re.search(pattern, f):
        problems.append(f"tracked file that looks like a secret or runtime data: {f}")

print("NOTES")
for n in notes:
    print("  -", n)
print("PROBLEMS" if problems else "PROBLEMS: none")
for p in problems:
    print("  -", p)
sys.exit(1 if problems else 0)