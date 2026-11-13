# Code guide

This file explains what each part of the code does, how the parts connect, and why
the security decisions were made. The [README](../README.md) explains how to *use* the
tool. Read this one if you want to *change* it.

## The big picture

There are two entry points and one engine:

```
npm run scan / make scan          (package.json, Makefile)
        │
        ▼
scripts/sandbox.py                 command front end: doctor, build, test, scan
        │  runs, once per folder
        ▼
scripts/screen.py  ──►  scripts/screening/cli.main()   the engine
                              │
        ┌─────────────────────┼───────────────────────────────┐
        ▼                     ▼                               ▼
  1. detect.py          2. checks.py (static)           3. dynamic.py (Python only)
  which ecosystems?     OSV-Scanner, GuardDog,          runs run_sandbox.sh, reads the
                        source patterns                 events, judges them
        │                     │                               │
        │                     └── runner.py                   └── run_sandbox.sh
        │                         Docker toolbox or local           │
        │                         tools                             ▼
        │                                              sandbox container (no network,
        │                                              read-only, no capabilities)
        │                                                    │
        │                                                    └── sandbox-install.sh
        │                                                        └── monitor/sitecustomize.py
        ▼
  4. models.py + report.py            verdict (pass / warn / block) and Markdown report
```

Two rules shape the whole design:

- **The host never runs untrusted code.** Packages are only ever installed inside the
  sandbox container. On the host, everything is read (or read by a scanner that is
  itself isolated).
- **Failure is closed.** If a check can't run, the report says so. If the sandbox
  output is missing or broken, the verdict is BLOCK, never PASS.

## Two layers of front-end code

| File | Purpose |
|---|---|
| `package.json` | Defines the npm command names (`npm run scan`). Each one calls `scripts/sandbox.py`. |
| `Makefile` | The same commands for `make` users. Nothing else. |
| `scripts/sandbox.py` | The one command-line entry point. Handles `doctor`, `build`, `test`, and `scan`. It checks Docker, builds the images on demand, and calls `screen.py` once per folder. Standard library only. |

`sandbox.py` never inspects a dependency itself. It only prepares the environment,
then hands each folder to the engine and reads the verdict from the engine's output
(`verdict: block`). That output line is the contract between the two.

## The engine: `scripts/screen.py` and `scripts/screening/`

`screen.py` is three lines of logic: it puts `scripts/` on the import path and calls
`screening.cli.main()`. It exists so the command `python3 scripts/screen.py <folder>`
keeps working.

The engine is a package. Each module has one job.

### `screening/models.py`: data types

- **`Finding`** is one result: a severity (`block`, `warn`, `info`), a stage
  (`static`, `dynamic`, `tool`), and a message. It is frozen (immutable), so findings
  can be compared and de-duplicated.
- **`Report`** holds everything one run produced: the ecosystems found, the coverage
  table data, findings, the raw runtime events, and notes about the tools.
  - `add()` checks the severity before adding a finding, so a typo fails loudly.
  - `dedupe()` removes repeats. pip runs `setup.py` twice (metadata, then wheel), so the
    same event can be logged twice.
  - `verdict` is the rule that turns findings into an answer: any BLOCK means block,
    otherwise any WARN means warn, otherwise pass. `info` never changes the verdict.

### `screening/detect.py`: find the ecosystems

- **`classify(name)`** maps a file name to an ecosystem. `requirements*.txt` and
  `setup.py` are `pypi`. `package-lock.json` is `npm`. `Gemfile.lock` and `*.gemspec`
  are `rubygems`. `go.sum` is `go`. To support a new file type, add it here.
- **`iter_files(root)`** walks the folder. It skips generated folders
  (`node_modules`, `.venv`, `build`, `dist`, and so on) and **skips symbolic links**.
  See [Security decisions](#security-decisions).
- **`detect_ecosystems(root)`** returns `{ecosystem: [manifest paths]}`. Every other stage
  starts from this.

### `screening/runner.py`: run the external scanners

This module decides *where* a scanner runs and makes sure it runs read-only.

- **`ToolCall`** describes one scanner run: the program name, its arguments, and whether
  it needs the network. `{target}` in the arguments is replaced by the folder path.
- **`choose_mode(local_tools)`** returns `docker` or `local` once per run. Docker is the
  default when it is running. `local` is used only with `--local-tools`, or when Docker is
  unavailable.
- **`docker_command(call, target)`** builds the `docker run` command. It applies:
  - `--network none` unless the tool needs the network (GuardDog: none; OSV-Scanner: allowed).
  - `--read-only`, a small `/tmp`, `--cap-drop=ALL`, `no-new-privileges`, user `10001`.
  - `--pids-limit`, `--memory`: bounded resources.
  - `--mount type=bind,...,readonly`: the target folder, read-only. `--mount` is used
    instead of `-v` because a colon or comma in a folder name can change what `-v` mounts.
- **`run_tool(call, target, mode, report)`** runs one call and records what happened in
  `report.tool_notes` (ran locally, ran in Docker, or skipped and why). It returns `None`
  when the tool could not run, so the caller can mark that check as skipped.
- **`ensure_toolbox_image()`** builds `supply-chain-tools:latest` from `Dockerfile.tools`
  the first time it is needed.

### `screening/checks.py`: the static stage

Nothing is installed or executed here. Files are read or scanners read them.

- **`check_known_vulnerabilities`** runs OSV-Scanner once, recursively, over the folder.
  It covers every ecosystem in one pass. Results are filtered to the ecosystems being
  screened (`OSV_NAMES` maps OSV's names to ours). Each vulnerable package becomes a WARN.
- **`check_heuristics`** runs GuardDog once per ecosystem, and parses its
  `N risks detected` line. A tool that prints something unexpected is recorded as `error`,
  not as clean.
- **`check_source_patterns`** scans Python files with regular expressions
  (`INSTALL_TIME_PATTERNS`): raw sockets, HTTP clients, process spawns, decode-and-execute,
  credential paths. Files over 2 MB are skipped and noted. These are heuristics, so
  matches are WARN, never BLOCK.
- **`run_static_checks`** runs the three in order. It also adds an INFO finding when
  `setup.py` exists, because installing such a package runs code.

### `screening/dynamic.py`: the sandbox stage (Python only)

This stage installs the package in the container and judges what it did.

- **`can_install(target)`**: only Python packages with `setup.py` or `pyproject.toml` can
  be installed in the sandbox. npm, RubyGems, and Go are not run yet.
- **`run_sandbox(target, image, report)`** starts `scripts/run_sandbox.sh` with a clean
  environment. It only passes the variables the Docker CLI needs (`PATH`, `HOME`, the image
  name), so host secrets are not passed in.
- **`parse_output(stdout)`** reads the sandbox output between markers: `::PIP_EXIT::`
  (install exit code) and `::EVENTS_BEGIN::` / `::EVENTS_END::` (the event log). It returns
  whether the markers were present, so a broken run can be detected. Event lines that are
  not valid JSON are counted and reported, not silently dropped.
- **`judge_events(events)`** is a pure function. It maps events to severities:
  - `network_connect`, `dns_lookup`, `sensitive_file_access`: **BLOCK**.
  - `write_outside_workdir`: WARN.
  - `process_spawn` of a program not in `EXPECTED_SPAWNS`: WARN. Routine build helpers
    (`uname`, `python3`, and so on) are expected and are not flagged.

  Keeping this function free of I/O lets the unit tests check every rule directly.

### `screening/report.py`: the Markdown report

- **`md(text)`** neutralizes text from the scanned package: it escapes `|` (table cells),
  replaces backticks (code spans), and joins lines. Package names and file paths are
  untrusted, and this stops them from breaking the layout.
- **`render(report, stamp)`** builds the report: verdict, coverage table, findings, raw
  events, tool notes. Tool output goes in a fenced block whose fence is longer than any
  backtick run inside it, so the block cannot be closed early.
- **`write_report(report, out)`** writes the file and creates the folder if needed.

### `screening/cli.py`: the orchestration

`main()` is the whole pipeline, in order:

1. Validate the target folder and the `--ecosystem` names.
2. `detect_ecosystems`. Stop with exit code 2 if nothing is found.
3. Pick the tool mode (`choose_mode`) and record it in the tool notes.
4. `run_static_checks`.
5. Unless `--skip-dynamic`: `run_sandbox` for Python packages. Other ecosystems get a note
   saying they were screened statically only.
6. `dedupe`, write the report, print the verdict. Exit 1 on BLOCK, else 0.

`parse_ecosystems` validates the `--ecosystem` value, so a typo is an error message, not a
silent empty result.

## The sandbox

### `Dockerfile`: the sandbox image

Python 3.13 slim, with a non-root user (`sandbox`, UID 10001), a planted fake `.env` file
(the honeytoken), and the runtime monitor copied to `/opt/monitor`. Two environment
settings matter: `PYTHONPATH` loads the monitor into every Python process, and
`PIP_NO_INDEX=1` stops pip from reaching a package index even if networking were allowed.

The image does not enforce isolation. Isolation is applied at `docker run` time by
`run_sandbox.sh`, so the same image can be tested with and without the restrictions.

### `scripts/run_sandbox.sh`: starts the container

Every isolation flag is set here, with a comment for each one. The candidate folder is
mounted with `--mount ...,readonly` at `/input`. The script exits with the container's exit
status, so `run_sandbox.sh` failing is visible to the caller.

### `scripts/sandbox-install.sh`: runs inside the container

1. Copies the package from the read-only `/input` to `/work/src`, which is writable.
2. Runs `pip install --no-deps --no-build-isolation --no-index --target /work/site`.
   No dependencies are fetched, and no network is used. Only the package itself runs.
3. Prints `::PIP_EXIT::<code>`, then the event log between `::EVENTS_BEGIN::` and
   `::EVENTS_END::`.

It always exits 0 after printing, so the host reads the output and judges it. A
copy failure exits non-zero (`set -e`), and the host then sees no markers and blocks.

### `monitor/sitecustomize.py`: the runtime monitor

Loaded into every Python process in the sandbox through `PYTHONPATH`. It registers an
audit hook (`sys.addaudithook`), which CPython calls for security-relevant operations:

| Audit event | Logged as |
|---|---|
| `socket.connect` | `network_connect` |
| `socket.getaddrinfo` (DNS) | `dns_lookup` |
| `open` on a sensitive path (`/.env`, `/.ssh/`, `/.aws/`, ...) | `sensitive_file_access` |
| `open` for writing outside the work folders | `write_outside_workdir` |
| `subprocess.Popen`, `os.system`, `os.exec` | `process_spawn` |

Details that matter when editing it:

- A thread-local flag stops the monitor from logging its own write to the event log.
- Relative paths are made absolute before checking, so `build/x` inside the work
  folder is recognized as work-folder output.
- Integer file descriptors are not paths, so they are skipped.

## The scanner toolbox: `Dockerfile.tools`

One image with OSV-Scanner and GuardDog, so neither has to be installed on the host.

- **OSV-Scanner** is downloaded from its release and checked against a SHA-256 value
  pinned in the Dockerfile (`OSV_SHA256_AMD64`, `OSV_SHA256_ARM64`). The checksum is
  not read from the release page, so a tampered release cannot also change the expected
  checksum. To upgrade, change the version and both checksums together.
- **GuardDog** is installed from PyPI at a pinned version. Its cache of popular package
  names is created at build time, and only that cache folder is writable by the scanner user.
- The default command is `osv-scanner`. `runner.py` overrides it with `--entrypoint` to run
  `guarddog`.

## Tests

| File | What it covers | Needs Docker? |
|---|---|---|
| `tests/test_screening.py` | Report escaping, parsing of sandbox output, the verdict rules, symlink skipping, Docker command flags | No |
| `tests/test_sandbox.py` | Isolation (no network, read-only, no capabilities, unprivileged user, no host paths or secrets), end-to-end verdicts, static-only checks | Yes, for the isolation and verdict tests |

Run both with `npm run test`. CI runs the same command.

## Security decisions

| Decision | Why |
|---|---|
| Scanners run in Docker by default | They parse files from an untrusted package. A bug in a parser should not run on your machine. `--local-tools` is the explicit opt-out. |
| GuardDog runs with no network | It only reads files. Removing the network means that, even if it were compromised by a crafted package, it could not send data out. |
| OSV-Scanner keeps network access | It must download the vulnerability database. It sends package names and versions to the OSV service, which is a privacy trade-off. |
| `--mount` instead of `-v` | Folder names containing `:` or `,` can change what `-v` mounts. `--mount` takes each option separately. A folder with a comma is refused with a note. |
| Symlinks are skipped on the host | A repository could link a file to something on the host, such as `~/.ssh/config`. The scanner reads only real files inside the folder. |
| Pinned OSV checksums | The published checksum file sits next to the binary on the same release page. Pinning the value in the repository means one compromised release cannot change both. |
| Fail closed on missing sandbox output | If the monitor's output markers are missing, the result is BLOCK. A broken or silently failing sandbox can't produce a PASS. |
| Malformed event lines are reported | A tampered or corrupt log is a warning, not silently ignored. |
| Report text is escaped | Package names and event details come from untrusted code. Without escaping, a name containing `|` or a backtick could break the report. |
| The folder goes after `--` in the action | A folder named `--something` can't be read as an option. |
| `contents: read` in workflows | The CI jobs only need to read the repository, so the token gets no write access. |
| Clean environment for the sandbox run | Only `PATH`, `HOME`, and the image name are passed. Host secrets such as cloud keys are not visible to the script. |

## Known gaps

These are real limits, and they are listed so nobody has to find them the hard way.

1. **The monitor shares a process with the package.** Package code can edit the event log
   file (it's in `/tmp`, which is writable), and so could hide its own events from the
   report. Its network attempts still fail, because the container has no network, but the
   report would not show them. The fix is to observe the sandbox from outside its process,
   for example with a separate logging container or with `strace`/eBPF. Not built yet.
2. **Only Python packages are installed.** npm, RubyGems, and Go packages get the static
   checks only. Installing them safely would need their runtimes in the sandbox image.
3. **The sandbox runs offline.** Packages are installed from the local folder. Registry
   downloads would need an egress proxy that allows only that registry.
4. **Base images are not digest-pinned.** `python:3.13-slim-bookworm` is a tag, and it can
   change. Pinning the digest (`@sha256:...`) would make builds reproducible.
5. **GuardDog is not hash-pinned.** It is pinned to a version, but not to file hashes. Installing
   with `--require-hashes` would close this.
6. **The sensitive-path list is hand-written.** It covers common credential locations and
   is not exhaustive.
7. **Action references are tags, not commit SHAs.** `actions/checkout@v4` and the examples
   use `@main` or `@v4`, which can move. Pinning to a commit SHA would make them fixed.

## How to change things

- **Add a file type for detection**: edit `classify()` in `screening/detect.py`.
- **Add a suspicious source pattern**: add a regex and label to `INSTALL_TIME_PATTERNS`
  in `screening/checks.py`.
- **Change what a sandbox event means**: edit `BLOCKING_EVENTS`, `WARN_EVENTS`, or
  `EXPECTED_SPAWNS` in `screening/dynamic.py`, and add a case to `DynamicParsingTests`.
- **Add a new external scanner**: build a `ToolCall`, call `runner.run_tool`, handle `None`
  (skipped), and record a coverage status with `report.cover`. Add its install to
  `Dockerfile.tools` so Docker mode works too.
- **Change the isolation**: edit `scripts/run_sandbox.sh` (the sandbox) or
  `docker_command` in `screening/runner.py` (the toolbox). Add a test in
  `tests/test_sandbox.py` for each flag you add or remove.
