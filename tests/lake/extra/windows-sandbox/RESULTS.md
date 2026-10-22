# Native Windows and WSL comparison

Recorded 2026-10-22 UTC. This is feasibility evidence for the Windows sandbox RFC,
not a supported `lake check` backend or a completed security assessment.

## Stack and source boundaries

1. PR #1 extracts sandbox launch construction.
2. PR #2 separates shared, Linux, and Windows modules.
3. PR #3 adds shared behavioral probes against Lake's Linux backend.
4. This draft adds the native Windows experiment, stronger descendant/space-path
   probes, a real Lean workflow, and these observations.

The successful Windows executions use the native source recorded in commit
`d912506`. A later change records a grant root before attempting DACL propagation,
so a partially failed update can be included in cleanup. That change compiles,
but its rebuilt driver is blocked by local Application Control (WinError 4551).
Its runtime behavior and the additional permission-restoration assertions have
**not** been verified. The reports distinguish these source boundaries.

The Linux sandbox module is unchanged from PR #2, commit `72e5b45`; the probe
fixtures used for the final Linux run match the fixture source in `d912506`.
The ordinary Windows backend continues to reject sandboxed checking.

## Environments

* Windows 11 x64, build 26200.9711; MSVC 19.44.35229, Release, `/W4 /WX`, static CRT.
* Dedicated WSL2 distribution `LeanSandbox`, Ubuntu 24.04, kernel
  `6.18.33.2-microsoft-standard-WSL2`, Bubblewrap 0.9.0. Linux tests run as ordinary
  user `leancheck` (UID 1000), from an ext4 checkout separate from Windows outputs.
* Both toolchains are Lean 4.35.0, commit
  `eb6cafb7290e8bd5f2937522d8d804f58f02bafc`, with their respective native binaries.
* WSL is configured without Windows PATH import or Windows executable interop.
  These tests compare the stated operations; they do not establish that WSL's
  complete host integration has the same boundary as a bare-metal Linux host.

## Observed results

| Experiment | Linux / WSL | Windows native experiment |
| --- | --- | --- |
| Shared behavioral probes | 13 pass | 13 pass on `d912506` native source |
| Build a fresh Lean project and export its proof data | Pass | Pass on `d912506` native source |
| `leanchecker`, `leanchecker-paranoid`, `lean4lean`, `nanoda_bin`, `con-ron` | All accept valid export | All accept valid export on `d912506` native source |
| `con-leche` | Accepts valid export | Process creation blocked by local Application Control, error 4551 |
| Replace the fixture theorem's proof with its proposition | Kernel rejects, exit 1 | Kernel rejects, exit 1, on `d912506` native source |
| Existing sandbox argument regressions | Pass | Pass |
| Current native source, fresh build directory | Not applicable | Clean compile and link; execution blocked by Application Control |
| Permission restoration and setup-failure audit | Not applicable | Blocked before driver launch; assertions not executed |

The behavior cases cover project reads, build writes, source/checker protection,
outside-file protection, inherited child restrictions, selected/omitted
environment variables, literal arguments, network denial and an online control,
and controller death while a child and grandchild are running. Tool and project
paths include spaces. The known linger probe retains inherited output handles;
pipe closure and Windows child liveness are used as lifetime evidence.

The Windows real-workflow record combines the valid-export run with a separate
corrected invalid-proof control; both used the same native source. They are not
represented as a single uninterrupted all-pass run. Windows did not complete a
full six-checker paranoid run because `con-leche` could not start.

## Engineering findings

* Hidden paths on Linux can be recreated inside its private tmpfs: the write
  operation may succeed while the original host file remains unchanged. Windows
  denied the same write. The common invariant is protection of the host file.
* This Windows launch requires `LOCALAPPDATA` in the explicit environment.
  Pointing it at a private writable directory worked in the tested setup.
* Attaching the Job Object at process creation avoids a separate interval in
  which a created child has not yet been placed into the job.
* A one-line junk file is an inadequate negative export control: the parser
  consumes the first line as metadata and can be left with no declarations.
  The actual negative control modifies the value expression of `sandboxProbe`
  in an otherwise valid export and requires kernel rejection with exit 1.
* Code Integrity events 3033/3077 confirm the local Application Control blocks
  for `con-leche`, an experimental DLL, and later native driver builds. No
  signing, enforcement, trust, registry, or security-policy settings were changed.

## Remaining work

Before a production backend can be considered, assess crash recovery for profile
and permission changes, alias/path races during grant setup and cleanup, default
AppContainer resource access versus LPAC, and integration with Lake's stream and
cancellation interfaces. Establish supported toolchains, dependency resolution,
authenticated repositories, Windows versions, and filesystems. Run the current
native source and permission-restoration assertions in an approved development
environment where the driver is permitted to execute.

The small project has no external dependencies and uses a TOML configuration.
Its successful build does not establish compatibility with arbitrary build
scripts, C/C++ dependencies, or private Git credentials. Writable roots in the
prototype must remain disposable, exclusively owned test directories.

Machine-readable receipts are under [results/](results/). Reproduction commands
for the native experiment are in [README.md](README.md). For this source
snapshot, standalone Linux Lake validation uses:

```sh
export PATH="$HOME/.elan/bin:$PATH"
export ELAN_TOOLCHAIN=leanprover/lean4:v4.35.0
tests/lake/run_test.sh tests/check-sandbox-args
tests/lake/run_test.sh tests/check-sandbox-confinement
cd tests/lake
lake env python3 extra/windows-sandbox/exercise-lean.py \
  --toolchain "$HOME/.elan/toolchains/leanprover--lean4---v4.35.0" \
  --report /tmp/lean-linux.json \
  --driver lean --run tests/check-sandbox-confinement/Driver.lean
```
