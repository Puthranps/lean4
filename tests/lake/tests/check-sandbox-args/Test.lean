module

import all Lake.Check.Sandbox

/-! Tests the process boundary used by `lake check` without requiring Linux namespaces. -/

open Lake.Check

def check (condition : Bool) (message : String) : IO Unit :=
  unless condition do throw <| IO.userError message

def positions (args needle : Array String) : Array Nat := Id.run do
  let mut found := #[]
  for i in [:args.size] do
    if args.extract i (i + needle.size) == needle then
      found := found.push i
  return found

def request : SandboxArgs := {
  cmd := "/tool chain/bin/lake"
  args := #["check", "a literal; $(argument)", "--"]
  envPass := #["LAKE_SANDBOX_TEST_PASS", "LAKE_SANDBOX_TEST_DELETE",
    "LAKE_SANDBOX_TEST_MISSING"]
  envOverride := #[("LAKE_SANDBOX_TEST_PASS", some "overridden"),
    ("LAKE_SANDBOX_TEST_DELETE", none), ("HOME", some "/untrusted-home")]
  readablePaths := #["/home/user/project with spaces", "/home/user/toolchain"]
  writablePaths := #["/home/user/project with spaces/.lake"]
  tmpfsPaths := #["/run", "/var"]
}

public def main : IO Unit := do
  let env ← sandboxEnv request
  check (env == #[("LAKE_SANDBOX_TEST_PASS", "overridden"), ("HOME", "/untrusted-home")])
    "only explicitly selected and overridden variables should reach the sandbox"

  let args := buildSandboxArgs request env "/home/user/project with spaces"
  check (args.contains "--unshare-all") "sandbox namespaces must be isolated"
  check (args.contains "--die-with-parent") "sandbox must track the parent's lifetime"
  check (args.contains "--clearenv") "sandbox environment must be cleared"
  check (!(args.contains "--share-net")) "network access must be disabled by default"
  check ((positions args #["--ro-bind", "/", "/"]).size == 1)
    "the host filesystem must be bound read-only"
  check ((positions args #["--tmpfs", "/home"]).size == 1)
    "the invoking user's home must be masked"
  check ((positions args #["--tmpfs", "/run"]).size == 1)
    "caller-specified hidden paths must be masked"
  let readGrants := positions args
    #["--ro-bind", "/home/user/project with spaces", "/home/user/project with spaces"]
  let writeGrants := positions args
    #["--bind", "/home/user/project with spaces/.lake", "/home/user/project with spaces/.lake"]
  check (readGrants.size == 1 && writeGrants.size == 1)
    "filesystem grants must preserve paths containing spaces"
  check (readGrants[0]! < writeGrants[0]!)
    "the writable build-directory grant must follow the read-only project grant"
  let inheritedHome := positions args #["--setenv", "HOME", "/untrusted-home"]
  let privateHome := positions args #["--setenv", "HOME", "/tmp/home"]
  check (inheritedHome.size == 1 && privateHome.size == 1 && inheritedHome[0]! < privateHome[0]!)
    "the sandbox's private home must override a supplied HOME"
  let tail := #["--chdir", "/home/user/project with spaces", "--", request.cmd] ++ request.args
  check (args.extract (args.size - tail.size) args.size == tail)
    "the command and literal arguments must follow the sandbox's option delimiter"

  let networkArgs := buildSandboxArgs { request with network := true } #[] "/project"
  check ((positions networkArgs #["--share-net"]).size == 1)
    "dependency fetching must be able to opt into networking"
  let cwdArgs := buildSandboxArgs { request with cwd := some "/private working directory" } #[] "/project"
  check ((positions cwdArgs #["--chdir", "/private working directory"]).size == 1)
    "an explicit working directory must override the project directory"

  let sandboxed ← Sandbox.mkSpawnArgs (.path "/sandbox wrapper/bwrap") "/usr/bin/env" "/project" request
  check (sandboxed.cmd == "/usr/bin/env") "the sandbox must launch through env"
  check (sandboxed.args.extract 0 2 == #["-i", "/sandbox wrapper/bwrap"])
    "the wrapper must start with a cleared environment and an unmodified executable path"
  check (sandboxed.cwd == some "/project") "the wrapper must start in the project directory"

  let direct ← Sandbox.mkSpawnArgs .noSandbox "/unused/env" "/project" request
  check (direct.cmd == request.cmd && direct.args == request.args)
    "explicitly unsandboxed execution must preserve the command and arguments"
  check (direct.cwd == some "/project" && direct.env == request.envOverride)
    "explicitly unsandboxed execution must preserve its environment and directory"
  IO.println "sandbox argument tests passed"
