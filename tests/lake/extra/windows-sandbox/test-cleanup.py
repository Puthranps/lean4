"""Check permission restoration and fail-closed setup on disposable NTFS trees."""
import argparse
import ctypes as c
from ctypes import wintypes as w
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


def security(path):
    advapi = c.WinDLL("advapi32", use_last_error=True)
    kernel = c.WinDLL("kernel32", use_last_error=True)
    get = advapi.GetNamedSecurityInfoW
    get.argtypes = [w.LPCWSTR, c.c_int, w.DWORD, c.c_void_p, c.c_void_p,
                   c.c_void_p, c.c_void_p, c.POINTER(c.c_void_p)]
    get.restype = w.DWORD
    convert = advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW
    convert.argtypes = [c.c_void_p, w.DWORD, w.DWORD, c.POINTER(c.c_void_p), c.c_void_p]
    convert.restype = w.BOOL
    kernel.LocalFree.argtypes = [c.c_void_p]
    kernel.LocalFree.restype = c.c_void_p
    descriptor, text = c.c_void_p(), c.c_void_p()
    flags = 4 | 16  # DACL and mandatory integrity label; no audit-SACL privilege.
    code = get(str(path), 1, flags, None, None, None, None, c.byref(descriptor))
    if code:
        raise OSError(code, "GetNamedSecurityInfoW")
    try:
        if not convert(descriptor, 1, flags, c.byref(text), None):
            raise c.WinError(c.get_last_error())
        try:
            return c.wstring_at(text)
        finally:
            kernel.LocalFree(text)
    finally:
        kernel.LocalFree(descriptor)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--driver", type=Path, required=True)
    parser.add_argument("--probe", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    options = parser.parse_args()
    driver = options.driver.resolve(strict=True)
    work = Path(__file__).resolve().parent / "work"
    work.mkdir(exist_ok=True)
    tests = []
    with tempfile.TemporaryDirectory(prefix="cleanup-", dir=work) as directory:
        root = Path(directory).resolve()
        assert root.is_relative_to(work.resolve())
        project, tools, scratch = [root / name for name in ("project", "tools", "scratch")]
        for path in (project, tools, scratch, project / ".lake"):
            path.mkdir()
        probe = tools / "probe.exe"
        shutil.copyfile(options.probe, probe)
        source = project / "source"
        source.write_text("canary\n")
        tracked = [project, source, tools, probe, project / ".lake", scratch]
        before = [security(path) for path in tracked]
        request = {
            "cmd": str(probe), "args": ["read", str(source)], "cwd": str(project),
            "readablePaths": [str(project), str(tools)],
            "writablePaths": [str(project / ".lake"), str(scratch)],
            "env": [("SystemRoot", os.environ["SystemRoot"]), ("LOCALAPPDATA", str(scratch))],
            "network": False,
        }
        request_file = root / "request.json"

        def check(name, expected):
            request_file.write_text(json.dumps(request), encoding="utf-8")
            try:
                result = subprocess.run([str(driver), str(request_file)], capture_output=True,
                                        text=True, timeout=30)
            except OSError as error:
                tests.append({"name": name, "status": "blocked-before-launch",
                              "winerror": error.winerror, "error": str(error)})
                print(f"BLOCKED {name}: {error}", flush=True)
                return False
            passed = result.returncode == expected and before == [security(path) for path in tracked]
            tests.append({"name": name, "passed": passed, "exit": result.returncode,
                          "stderr": result.stderr})
            print(f"{'PASS' if passed else 'FAIL'} {name}", flush=True)
            return True

        if check("restore-permissions-after-success", 0):
            request["cmd"] = str(tools / "missing.exe")
            check("restore-permissions-after-launch-failure", 2)
            request["cmd"] = str(probe)
            alias = project / "hard-link"
            os.link(source, alias)
            check("reject-hard-linked-grant-tree", 2)
            # Remove only this task-created alias, within the verified fixture root.
            alias.unlink()
    options.report.parent.mkdir(parents=True, exist_ok=True)
    options.report.write_text(json.dumps({"tests": tests}, indent=2))
    return int(any(not test.get("passed", False) for test in tests))


if __name__ == "__main__":
    raise SystemExit(main())
