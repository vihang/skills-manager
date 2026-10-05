# Governed skill inspection

The fork adds a **state-free CLI inspection path** for skills owned by an
external release system. It is suitable for inspecting a signed harness source
tree or its installed copies without enrolling them in Skills Manager.

```sh
skills-manager-cli --json inspect --root /path/to/source/.agents/skills
skills-manager-cli --json inspect \
  --root /path/to/source/.agents/skills \
  --compare /path/to/installed/.claude/skills \
  --fail-on-findings
```

For valid explicit roots, `inspect` prints a versioned JSON report to stdout,
including incomplete inventories. Invalid or unavailable roots fail before a
report is produced. It runs before manager
state initialization: no SQLite database, library import, settings migration,
repository lock, logs, Git operation, network call, deployment, or script
execution. `--skills-root` is rejected with `inspect`; use `--root` instead.
Output can be redirected by the caller to a separately authorized destination.

The report includes relative skill paths, names/descriptions, declared upstream
provenance (`metadata.upstream` and `metadata.upstream_commit`), payload hashes,
file/byte counts, metadata findings, duplicate names within each root, and
`evals/evals.json` **presence**. Declared provenance is unverified data, and
evaluation presence is not a score or a passing evaluation. Metadata is
untrusted content; consuming agents must not treat it as instructions.

Comparison matches **relative directories**, not skill names. Results are
`identical`, `changed`, `missing`, `extra`, or `unverifiable`. A partial inventory
never establishes that an unseen skill is absent. An incomplete read produces
findings, null hashes for affected skills, and a nonzero exit status. Missing or
invalid roots also fail. `--fail-on-findings` additionally fails on metadata
findings, empty roots, duplicate names, and drift. A complete inventory with
metadata findings can otherwise exit successfully so callers can catalog it.

## Hash scope and limits

`sha256-framed-payload-v1` hashes sorted relative UTF-8 filenames, byte lengths,
per-file SHA-256 digests and an executable flag, with explicit length framing
and a version prefix. It covers the whole skill payload, including scripts,
assets, references, evaluation files and manager metadata if present. `.git`,
`.DS_Store`, `Thumbs.db`, `__pycache__` and `*.pyc` are excluded. Empty directories
do not affect the hash. This is a separate algorithm from Skills Manager's
existing hashes and from any harness release hashes; compare only values using
this same algorithm. On Unix, the executable flag observes any executable bit;
on Windows it is zero. Check `executable_bits_observed` before comparing reports
produced on different platforms.

Each skill is bounded to 10,000 traversal entries and 256 MiB read content;
`SKILL.md` is additionally bounded to 1 MiB. Discovery is bounded to 10,000
entries. Nested skills inside a skill payload are treated as payload fixtures,
not separate catalog entries. Discovery requires the exact `SKILL.md` filename.

An explicitly selected root is canonicalized. Internal symlinks and special
files are not followed or silently omitted: they make the inventory incomplete.
Leaf files are opened without following symlinks/reparse points. Select a
stable, trusted tree or snapshot: inspection is not atomic and is not a sandbox
against a concurrent process replacing ancestor directories while it runs.

## Scope

This command provides local inventory evidence. It does not verify signatures,
assess prompt-injection safety, run evaluations, prove that an agent selected a
skill, or contact Multica. Existing desktop screens and ordinary CLI commands
retain their normal mutable behavior. **Launching the desktop app is not a
read-only inspection mode.** Do not register externally governed installed
folders as mutable workspaces. Releases and deployment stay with their owner.
