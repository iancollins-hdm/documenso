#!/usr/bin/env python3
"""Supply-chain check: lockfiles + known-malicious packages.

Runs in CI with nothing but the Python standard library (no pip install, no
third-party action), so the check itself adds no new supply chain.

What it does, for every manifest in the repository (node_modules and .git skipped):
  1. Lockfile rules (BLOCKING)
     - every package.json that declares dependencies has a lockfile next to it
       (package-lock.json, pnpm-lock.yaml, yarn.lock or bun.lock), or in a parent
       folder for workspaces;
     - npm: every dependency named in package.json is present in the lockfile's
       root entry with the same range (the first thing `npm ci` checks), so the
       lockfile cannot drift from package.json;
     - requirements*.txt: every line is pinned with == (no >=, no bare names).
  2. Known-malicious packages (BLOCKING)
     Every locked package@version is sent to the OSV database (api.osv.dev,
     Google's open vulnerability database, which carries the OpenSSF
     malicious-packages feed as MAL-* ids). Any MAL-* hit fails the run.
  3. Known vulnerabilities (REPORT ONLY)
     Critical/high counts are written to the job summary. Dependabot alerts are
     where these get fixed; this keeps the run from red-walling unrelated PRs.

Exit code 1 on any blocking finding. `--json PATH` writes the full result, which
the daily threat watch reads.
"""
import json, os, re, sys, urllib.request

ROOT = os.getcwd()
SKIP_DIRS = {"node_modules", ".git", "vendor", "dist", "build", ".next"}
LOCKS = ("package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "npm-shrinkwrap.json")
OSV = "https://api.osv.dev/v1/querybatch"

errors, notes = [], []
packages = {}  # (ecosystem, name, version) -> set(lockfile)


def add(eco, name, ver, src):
    if name and ver and not ver.startswith(("link:", "file:", "workspace:")):
        packages.setdefault((eco, name, ver), set()).add(src)


def rel(p):
    return os.path.relpath(p, ROOT)


def parse_npm_lock(path):
    data = json.load(open(path))
    for key, meta in data.get("packages", {}).items():
        if "node_modules/" in key and not meta.get("link"):
            add("npm", meta.get("name") or key.rsplit("node_modules/", 1)[-1], meta.get("version"), rel(path))
    return data


def parse_pnpm_lock(path):
    text = open(path).read()
    # pnpm v6-v9: package keys look like  /name@1.2.3:  'name@1.2.3':  '@s/n@1.2.3(peer@x)':
    for m in re.finditer(r"^  ['\"]?/?(@?[^@\s'\"/][^@\s'\"]*)@([0-9][^\s:'\"(]*)", text, re.M):
        add("npm", m.group(1), m.group(2), rel(path))


def parse_bun_lock(path):
    for m in re.finditer(r'\[\s*"(@?[^@"]+)@([0-9][^"]*)"', open(path).read()):
        add("npm", m.group(1), m.group(2), rel(path))


def parse_yarn_lock(path):
    text = open(path).read()
    for m in re.finditer(r'^"?(@?[^@\s"]+)@[^\n]*\n\s+version:? "?([^"\n]+)"?', text, re.M):
        add("npm", m.group(1), m.group(2), rel(path))


def parse_deno_lock(path):
    try:
        data = json.load(open(path))
    except Exception:
        return
    for key in (data.get("npm") or {}):
        m = re.match(r"(@?[^@]+)@([0-9][^_]*)", key)
        if m:
            add("npm", m.group(1), m.group(2), rel(path))


def check_requirements(path):
    for n, line in enumerate(open(path), 1):
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "git+", "http")):
            continue
        m = re.match(r"([A-Za-z0-9_.\-]+)(\[[^\]]*\])?\s*==\s*([^\s;]+)", line)
        if m:
            add("PyPI", m.group(1), m.group(3), rel(path))
        else:
            errors.append(f"{rel(path)}:{n}: `{line}` is not pinned with == (an unpinned install takes whatever is newest, including a just-published malicious release)")


def find_lock(start):
    d = start
    while True:
        for name in LOCKS:
            if os.path.exists(os.path.join(d, name)):
                return os.path.join(d, name)
        if os.path.abspath(d) == ROOT or d in ("/", ""):
            return None
        d = os.path.dirname(d)


def check_npm_sync(pkg_path, lock_path, lock_data):
    pkg = json.load(open(pkg_path))
    key = os.path.relpath(os.path.dirname(pkg_path), os.path.dirname(lock_path))
    key = "" if key == "." else key.replace(os.sep, "/")
    entry = lock_data.get("packages", {}).get(key)
    if entry is None:
        errors.append(f"{rel(pkg_path)}: not in {rel(lock_path)} (run `npm install` and commit the lockfile)")
        return
    for field in ("dependencies", "devDependencies", "optionalDependencies"):
        want, have = pkg.get(field) or {}, entry.get(field) or {}
        for name, rng in want.items():
            if have.get(name) != rng:
                errors.append(f"{rel(pkg_path)}: {field} {name}@{rng} does not match {rel(lock_path)} ({have.get(name)}); the lockfile is out of date")


lock_cache = {}
for dirpath, dirnames, filenames in os.walk(ROOT):
    dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
    fs = set(filenames)
    present = [l for l in LOCKS if l in fs]
    if len(present) > 1:
        notes.append(f"{rel(dirpath) or '.'}: more than one lockfile ({', '.join(present)}); keep the one your installs use and delete the others, or two different dependency trees can ship")
    for name in present:
        p = os.path.join(dirpath, name)
        try:
            if name in ("package-lock.json", "npm-shrinkwrap.json"):
                lock_cache[p] = parse_npm_lock(p)
            elif name == "pnpm-lock.yaml":
                parse_pnpm_lock(p)
            elif name == "bun.lock":
                parse_bun_lock(p)
            elif name == "yarn.lock":
                parse_yarn_lock(p)
        except Exception as e:
            errors.append(f"{rel(p)}: could not parse ({e})")
    if "deno.lock" in fs:
        parse_deno_lock(os.path.join(dirpath, "deno.lock"))
    for name in fs:
        if re.match(r"requirements.*\.txt$", name):
            check_requirements(os.path.join(dirpath, name))
    if "package.json" in fs:
        p = os.path.join(dirpath, "package.json")
        try:
            pkg = json.load(open(p))
        except Exception as e:
            errors.append(f"{rel(p)}: not valid JSON ({e})")
            continue
        if not any(pkg.get(k) for k in ("dependencies", "devDependencies", "optionalDependencies")):
            continue
        lock = find_lock(dirpath)
        if not lock:
            errors.append(f"{rel(p)}: has dependencies but no lockfile; installs are not reproducible")
        elif os.path.basename(lock) in ("package-lock.json", "npm-shrinkwrap.json"):
            if lock not in lock_cache:
                try:
                    lock_cache[lock] = json.load(open(lock))
                except Exception:
                    continue
            check_npm_sync(p, lock, lock_cache[lock])

# ---- OSV lookup
keys = sorted(packages)
malicious, vulns = [], {}
try:
    for i in range(0, len(keys), 500):
        chunk = keys[i:i + 500]
        body = json.dumps({"queries": [{"package": {"ecosystem": e, "name": n}, "version": v} for e, n, v in chunk]}).encode()
        req = urllib.request.Request(OSV, data=body, headers={"Content-Type": "application/json"})
        res = json.load(urllib.request.urlopen(req, timeout=120))["results"]
        for k, r in zip(chunk, res):
            ids = [x["id"] for x in r.get("vulns", [])]
            mal = [x for x in ids if x.startswith("MAL-")]
            if mal:
                malicious.append({"ecosystem": k[0], "name": k[1], "version": k[2], "ids": mal, "files": sorted(packages[k])})
            other = [x for x in ids if not x.startswith("MAL-")]
            if other:
                vulns[f"{k[0]}:{k[1]}@{k[2]}"] = other
except Exception as e:
    errors.append(f"OSV lookup failed ({e}); malicious-package check did not run")

for m in malicious:
    errors.append(f"MALICIOUS PACKAGE {m['name']}@{m['version']} ({', '.join(m['ids'])}) in {', '.join(m['files'])}. Do not install. Treat any machine that installed it as compromised.")

summary = [
    "## Supply-chain check",
    f"- Locked packages checked: **{len(keys)}**",
    f"- Known-malicious packages: **{len(malicious)}**",
    f"- Packages with a published advisory (report only; Dependabot alerts track fixes): **{len(vulns)}**",
]
if errors:
    summary.append("\n### Must fix\n" + "\n".join(f"- {e}" for e in errors))
if notes:
    summary.append("\n### Notes\n" + "\n".join(f"- {n}" for n in notes))
out = "\n".join(summary)
print(out)
if os.environ.get("GITHUB_STEP_SUMMARY"):
    with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as f:
        f.write(out + "\n")
if "--json" in sys.argv:
    json.dump({"packages": len(keys), "malicious": malicious, "advisories": vulns, "errors": errors},
              open(sys.argv[sys.argv.index("--json") + 1], "w"), indent=1)
sys.exit(1 if errors else 0)
