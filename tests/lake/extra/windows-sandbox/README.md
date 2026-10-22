# Native Windows sandbox experiment

This opt-in prototype tests AppContainer file/network restrictions and Job Object
lifetime management in a native library. The calling process owns the job and
waits for its child, matching a possible future Lake native binding. The static
test driver is a trusted caller for that binding, not a proposed production helper.
Windows `lake check` continues to reject sandboxed execution.

Build from a Visual Studio developer shell, using a fresh build directory:

```powershell
cmake -S tests/lake/extra/windows-sandbox -B build/windows-sandbox-static -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build/windows-sandbox-static
python tests/lake/tests/check-sandbox-confinement/run.py --probe build/windows-sandbox-static/probe.exe --report build/windows-sandbox-static/windows.json --driver build/windows-sandbox-static/sandbox-driver.exe
python tests/lake/extra/windows-sandbox/test-cleanup.py --probe build/windows-sandbox-static/probe.exe --driver build/windows-sandbox-static/sandbox-driver.exe --report build/windows-sandbox-static/cleanup.json
python tests/lake/extra/windows-sandbox/exercise-lean.py --toolchain "$env:USERPROFILE/.elan/toolchains/leanprover--lean4---v4.35.0" --report build/windows-sandbox-static/lean-windows.json --driver build/windows-sandbox-static/sandbox-driver.exe
```

The request is trusted controller input. Readable roots receive read/execute
grants for a fresh AppContainer SID; writable roots also receive data-write and
delete access and a low integrity label. The library restores root labels,
removes that SID's grants, and deletes the profile during ordinary cleanup.
Setup or cleanup failures are distinct from child exit codes. The child receives
an explicit environment and only duplicated standard-stream handles. The job
is attached atomically at process creation and does not permit breakaway.

Use only disposable, exclusively owned test trees for writable roots. This is
not a supported sandbox backend or a complete security boundary. In particular:

* Controller termination kills job members but cannot execute profile/ACL
  cleanup. The behavior harness removes its crashed controller's test profile
  and deletes its disposable grant trees. Production crash recovery for
  persistent permission changes is not implemented.
* Existing reparse points and hard links in grant trees are rejected. The
  prototype does not establish safety under concurrent path changes or aliases
  created after validation, including during permission cleanup.
* Regular AppContainer's default resource access is retained; LPAC and its
  compatibility with the Lean toolchain are not established.
* Network capability is Internet-client access, not a host/port allowlist.
* Supported runtime resources, private dependency credentials, network shares,
  cross-session behavior, and full adversarial object access remain unassessed.
* The library is synchronous and uses the caller's standard streams. Integration
  with Lake's child-process handles, asynchronous I/O, and cancellation is still
  required; the existing `mkSpawnArgs` interface cannot express these resources.

`exercise-lean.py` checks all six bundled checker executables by default and
requires exit 1 when the fixture theorem's proof is replaced by its proposition.
It does not equate a parser failure or launcher setup failure with kernel
rejection. `--checkers` selects an explicit subset, recorded in the report.

The behavioral reports must be read alongside these limits. Passing the probes
does not justify enabling the Windows backend in Lake.

Primary references: [launching AppContainer](https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer),
[process attributes](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute),
[Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects),
and [DACL updates](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-setnamedsecurityinfow).
