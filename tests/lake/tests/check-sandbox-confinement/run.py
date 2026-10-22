"""Exercise real access checks; use the same fixtures on Linux and Windows."""
import argparse
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--driver", nargs=argparse.REMAINDER, required=True,
                        help="launcher command; JSON request path is appended")
    parser.add_argument("--probe", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--network-ip", default="1.1.1.1")
    parser.add_argument("--network-port", type=int, default=443)
    options = parser.parse_args()
    probe = options.probe.resolve(strict=True)
    work = Path(__file__).resolve().parent / "work"
    work.mkdir(exist_ok=True)
    results = []
    with tempfile.TemporaryDirectory(prefix="behavior-", dir=work) as directory:
        root = Path(directory).resolve()
        assert root.is_relative_to(work.resolve()), "cleanup must remain in test work directory"
        project = root / "project with spaces"
        outputs = project / ".lake"
        outputs.mkdir(parents=True)
        source = project / "Main.lean"
        source.write_text("original source\n")
        outside = root / "outside.txt"
        outside.write_text("private\n")
        # Put the probe and canary in a dedicated read-only tool directory.
        tools = root / "tools"
        tools.mkdir()
        target = tools / probe.name
        shutil.copyfile(probe, target)
        target.chmod(0o755)
        checker = tools / "checker-canary"
        checker.write_text("original checker\n")
        request_file = root / "request.json"
        scratch = root / "scratch"
        scratch.mkdir()
        env = [("LEAN_SANDBOX_PASSED", "passed"), ("TMP", str(scratch)),
               ("TEMP", str(scratch)), ("TMPDIR", str(scratch))]
        if os.name == "nt":
            env.append(("SystemRoot", os.environ["SystemRoot"]))
            env.append(("LOCALAPPDATA", str(scratch)))

        def request(arguments, network=False):
            request_file.write_text(json.dumps({
                "cmd": str(target), "args": arguments, "cwd": str(project),
                "readablePaths": [str(project), str(tools)],
                "writablePaths": [str(outputs), str(scratch)],
                "env": env, "network": network,
            }), encoding="utf-8")
            return [*options.driver, str(request_file)]

        def check(name, arguments, expected=0, network=False, stdout=None):
            completed = subprocess.run(request(arguments, network), capture_output=True,
                                       text=True, timeout=30)
            passed = completed.returncode in expected if isinstance(expected, tuple) else completed.returncode == expected
            if stdout is not None:
                passed = passed and completed.stdout == stdout
            results.append({"name": name, "passed": passed,
                            "expected": expected, "actual": completed.returncode,
                            "stdout": completed.stdout, "stderr": completed.stderr})
            print(f"{'PASS' if passed else 'FAIL'} {name}", flush=True)
            if not passed:
                print(f"  exit {completed.returncode}, expected {expected}: {completed.stderr.strip()}", flush=True)

        os.environ["LEAN_SANDBOX_SECRET"] = "must not be inherited"
        check("read-project", ["read", str(source)])
        check("write-build-output", ["write", str(outputs / "generated")])
        check("deny-source-write", ["write", str(source)], 10)
        check("deny-checker-write", ["write", str(checker)], 10)
        check("deny-outside-read", ["read", str(outside)], 10)
        # A hidden path may be recreated in Linux's private tmpfs. It must not
        # modify the original host file, regardless of the operation's exit code.
        check("protect-outside-host-write", ["write", str(outside)], (0, 10))
        results[-1]["passed"] = results[-1]["passed"] and outside.read_text() == "private\n"
        check("child-inherits-restrictions", ["spawn-write", str(checker)], 10)
        check("selected-environment", ["env", "LEAN_SANDBOX_PASSED", "passed"])
        check("omit-other-environment", ["env", "LEAN_SANDBOX_SECRET", "<absent>"])
        literal = "a literal; $(argument) with spaces"
        check("literal-arguments", ["args", literal, "", 'quoted"value', "trailing\\"],
              stdout=literal + '\n\nquoted"value\ntrailing\\\n')
        endpoint = (options.network_ip, options.network_port)
        try:
            with socket.create_connection(endpoint, timeout=3):
                pass
        except OSError as error:
            results.append({"name": "network-controls", "skipped": str(error)})
            print(f"SKIP network controls: host cannot reach {endpoint}: {error}")
        else:
            arguments = ["network", endpoint[0], str(endpoint[1])]
            check("deny-network", arguments, 10)
            check("allow-network", arguments, network=True)

        pidfile = outputs / "child.pid"
        launched = subprocess.Popen(request(["linger", str(pidfile)]),
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        pid = None
        started = False
        try:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                if pidfile.exists():
                    try:
                        pid = int(pidfile.read_text())
                        started = True
                        if os.name != "nt":
                            # The probe sees a namespace PID; obtain its host PID
                            # from our own process tree before testing liveness.
                            pending = [launched.pid]
                            pid = None
                            while pending:
                                candidate = pending.pop()
                                proc = Path("/proc") / str(candidate)
                                try:
                                    if (proc / "comm").read_text().strip() == target.name:
                                        pid = candidate
                                        break
                                    pending.extend(map(int, (proc / "task" / str(candidate) / "children").read_text().split()))
                                except FileNotFoundError:
                                    pass
                        break
                    except ValueError:
                        pass
                if launched.poll() is not None:
                    break
                time.sleep(0.05)
            launched.kill()
            launched.communicate(timeout=10)
            alive = True
            if pid is not None:
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    alive = subprocess.run([str(probe), "alive", str(pid)]).returncode == 0
                    if not alive:
                        break
                    time.sleep(0.05)
            # communicate() returning proves closure of the inherited output
            # pipes. The known linger probe holds them open for its lifetime.
            passed = started and (os.name != "nt" or (pid is not None and not alive))
            results.append({"name": "launcher-death-kills-child", "passed": passed,
                            "started": started, "host_pid": pid, "output_pipes_closed": True})
            print(f"{'PASS' if passed else 'FAIL'} launcher-death-kills-child")
        finally:
            if launched.poll() is None:
                launched.kill()
                launched.communicate(timeout=10)
            if pid is not None and subprocess.run([str(probe), "alive", str(pid)]).returncode == 0:
                if os.name == "nt":
                    subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], capture_output=True)
                else:
                    import signal
                    os.kill(pid, signal.SIGKILL)
            if os.name == "nt":
                # The killed test controller cannot remove its persistent profile.
                # All its grant roots belong to this disposable fixture.
                import ctypes
                delete_profile = ctypes.WinDLL("userenv").DeleteAppContainerProfile
                delete_profile.argtypes = [ctypes.c_wchar_p]
                delete_profile.restype = ctypes.c_long
                prefix = f"leanprobe.{launched.pid}."
                packages = Path(os.environ["LOCALAPPDATA"]) / "Packages"
                for profile in packages.iterdir():
                    if profile.name.casefold().startswith(prefix):
                        if delete_profile(profile.name) < 0:
                            raise RuntimeError("could not remove crashed test controller's profile")
        if source.read_text() != "original source\n" or checker.read_text() != "original checker\n":
            results.append({"name": "protected-canaries-unchanged", "passed": False})
    options.report.parent.mkdir(parents=True, exist_ok=True)
    options.report.write_text(json.dumps({"platform": sys.platform, "tests": results}, indent=2))
    return int(any(item.get("passed") is False for item in results))


if __name__ == "__main__":
    raise SystemExit(main())
