"""Build/export a disposable Lean project and replay it with bundled checkers."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--toolchain", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--checkers", default="leanchecker,leanchecker-paranoid,lean4lean,nanoda_bin,con-leche,con-ron")
    parser.add_argument("--driver", nargs=argparse.REMAINDER, required=True)
    options = parser.parse_args()
    toolchain = options.toolchain.resolve(strict=True)
    suffix = ".exe" if os.name == "nt" else ""
    binary = lambda name: str(toolchain / "bin" / (name + suffix))
    work = Path(__file__).resolve().parent / "work"
    work.mkdir(exist_ok=True)
    tests = []
    with tempfile.TemporaryDirectory(prefix="lean-", dir=work) as directory:
        root = Path(directory).resolve()
        assert root.is_relative_to(work.resolve())
        project = root / "project with spaces"
        project.mkdir()
        (project / ".lake").mkdir()
        (project / "lakefile.toml").write_text(
            'name = "sandbox_demo"\ndefaultTargets = ["Demo"]\n'
            '[[lean_lib]]\nname = "Demo"\n')
        (project / "Demo.lean").write_text("theorem sandboxProbe : 2 + 2 = 4 := rfl\n")
        # This fixture has no dependencies or executable configuration.
        (project / "lake-manifest.json").write_text(json.dumps({
            "version": "1.3.0", "packagesDir": ".lake/packages", "packages": [],
            "name": "sandbox_demo", "lakeDir": ".lake", "fixedToolchain": False,
        }))
        scratch = root / "scratch"
        scratch.mkdir()
        exports = root / "exports"
        exports.mkdir()
        export = exports / "proof.ndjson"
        env = [("PATH", str(toolchain / "bin") + os.pathsep + ("/usr/bin:/bin" if os.name != "nt" else "")),
               ("TMP", str(scratch)), ("TEMP", str(scratch)), ("TMPDIR", str(scratch)),
               ("HOME", str(scratch)), ("LEAN_ABORT_ON_PANIC", "1")]
        if os.name == "nt":
            env.extend([("SystemRoot", os.environ["SystemRoot"]), ("LOCALAPPDATA", str(scratch))])
        request_file = root / "request.json"

        def launch(name, cmd, args, build=False, output=None, reject=False):
            request_file.write_text(json.dumps({
                "cmd": cmd, "args": args, "cwd": str(project if build else scratch),
                "readablePaths": [str(project), str(toolchain), str(exports)],
                "writablePaths": [str(project / ".lake"), str(scratch)] if build else [str(scratch)],
                "env": env + ([("LAKE_CHECK_EXPORT", "1")] if build else []), "network": False,
            }), encoding="utf-8")
            with open(output if output else os.devnull, "wb") as stream:
                result = subprocess.run([*options.driver, str(request_file)], stdout=stream,
                                        stderr=subprocess.PIPE, timeout=180)
            # Setup errors are not proof rejections. A checker rejection must
            # come from a launched checker, not from failure to create its sandbox.
            passed = result.returncode == (1 if reject else 0)
            tests.append({"name": name, "passed": passed, "exit": result.returncode,
                          "stderr": result.stderr.decode("utf-8", errors="replace")})
            print(f"{'PASS' if passed else 'FAIL'} {name}", flush=True)
            if not passed:
                print(tests[-1]["stderr"], flush=True)
            return passed

        built = launch("build-and-export", binary("lake"), ["check"], build=True, output=export)
        if built and export.stat().st_size:
            config = exports / "nanoda.json"
            config.write_text(json.dumps({
                "use_stdin": False, "export_file_path": str(export),
                "permitted_axioms": ["propext", "Classical.choice", "Quot.sound"],
                "unpermitted_axiom_hard_error": False, "num_threads": 4,
                "nat_extension": True, "string_extension": True,
            }))
            for name, args in [
                ("leanchecker", ["--silent", "--from-export", str(export)]),
                ("leanchecker-paranoid", ["--silent", "--from-export", str(export)]),
                ("lean4lean", ["--import", str(export)]),
                ("nanoda_bin", [str(config)]),
                ("con-leche", [str(export)]), ("con-ron", [str(export)]),
            ]:
                if name in options.checkers.split(","):
                    launch(name, binary(name), args)
            corrupted = exports / "corrupted.ndjson"
            probe_name = None
            changed = False
            with export.open(encoding="utf-8") as original, corrupted.open("w", encoding="utf-8") as modified:
                for line in original:
                    item = json.loads(line)
                    if item.get("str", {}).get("str") == "sandboxProbe" and item["str"].get("pre") == 0:
                        probe_name = item["in"]
                    if probe_name is not None and item.get("thm", {}).get("name") == probe_name:
                        # Use the proposition itself where its proof is required.
                        # This remains a syntactically valid export with a bad proof.
                        item["thm"]["value"] = item["thm"]["type"]
                        line = json.dumps(item) + "\n"
                        changed = True
                    modified.write(line)
            if not changed:
                raise RuntimeError("did not find the fixture theorem in the export")
            launch("reject-invalid-proof", binary("leanchecker"),
                   ["--silent", "--from-export", str(corrupted)], reject=True)
        elif built:
            tests.append({"name": "nonempty-export", "passed": False})
        version = subprocess.run([binary("lean"), "--version"], capture_output=True, text=True, check=True).stdout.strip()
        report = {"platform": os.name, "toolchain": version,
                  "selectedCheckers": options.checkers.split(","), "tests": tests}
        options.report.parent.mkdir(parents=True, exist_ok=True)
        options.report.write_text(json.dumps(report, indent=2))
    return int(any(not test["passed"] for test in tests))


if __name__ == "__main__":
    raise SystemExit(main())
