# Sandbox behavior probes

These tests execute real file and network operations, including an operation in a
spawned child. Linux requests go through `Sandbox.Linux.mkSpawnArgs`, so argument
construction remains in Lake. A Windows driver can consume the same JSON request
format. No native Windows backend is enabled by this test fixture.

Run the Linux baseline as an ordinary user with Bubblewrap and a C++ compiler:

```sh
tests/lake/run_test.sh tests/check-sandbox-confinement
```

`run.py` accepts a driver command and appends the path to a JSON request. The
request names the executable, literal arguments, working directory, read and
write grants, complete environment, and whether to allow networking. A driver
must return the child's exit code, must fail closed on setup errors, and must
not let the child survive termination of the driver. Request files are trusted
controller input; they are not supplied by a project under evaluation.

The network cases first require a successful host connection to the same
endpoint. An unreachable endpoint is reported as a skipped control, not evidence
of isolation. The default endpoint is `1.1.1.1:443`; use `--network-ip` and
`--network-port` to select another reachable TCP service.

Reports are written under ignored `work/`. Fixtures are fresh directories there;
the tests never attempt to overwrite a real source file or checker executable.
These probes are evidence about particular operations, not a complete security
assessment. They do not establish protection against all Windows object types,
filesystem aliases, services, or native-code exploits.
