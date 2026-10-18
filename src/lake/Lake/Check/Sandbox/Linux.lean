/-
Copyright (c) 2025 Lean FRO, LLC. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Henrik Böving
-/
module

prelude
public import Lake.Check.Sandbox.Types
import Init.Data.ToString.Macro

namespace Lake.Check.Sandbox.Linux

public def forbiddenPaths : Array System.FilePath := #["/run", "/var"]

/--
Builds the `bwrap` command line.

`/` is bound read-only and the home directories are then covered with a `tmpfs`, so the code being
judged is built against the system it expects while none of the invoking user's files are readable.
Mounts apply in order, so `readablePaths` binds back what the run does need on top of those covers.
Only the paths in `writablePaths` are writable, and the network is a namespace rather than a filter:
a run either has one or has none at all.
-/
public def buildArgs (spawnArgs : SandboxArgs) (env : Array (String × String))
    (projectDir : System.FilePath) : Array String :=
  let args := #[
    "--ro-bind", "/", "/",
    "--tmpfs", "/home",
    "--tmpfs", "/root",
    "--tmpfs", "/run/user",
    "--tmpfs", "/tmp",
    "--dir", "/tmp/home",
    "--dev", "/dev",
    "--proc", "/proc",
    "--clearenv"
  ]
  let args := spawnArgs.tmpfsPaths.foldl (init := args)
    (fun acc path => acc ++ #["--tmpfs", path.toString])
  let args := spawnArgs.readablePaths.foldl (init := args)
    (fun acc path => acc ++ #["--ro-bind", path.toString, path.toString])
  let args := spawnArgs.writablePaths.foldl (init := args)
    (fun acc path => acc ++ #["--bind", path.toString, path.toString])
  let args := env.foldl (init := args) (fun acc (name, value) => acc ++ #["--setenv", name, value])
  -- Set last, so it wins over an inherited one: the invoking user's `HOME` is no longer there to
  -- point at, and `git` and Lake's caches want somewhere writable. This one goes with the run.
  let args := args ++ #[
    "--setenv", "HOME", "/tmp/home",
    "--unshare-all",
    "--die-with-parent",
    "--new-session"
  ]
  let args := if spawnArgs.network then args ++ #["--share-net"] else args
  let args :=
    if let some cwd := spawnArgs.cwd then
      args ++ #["--chdir", cwd.toString]
    else
      args ++ #["--chdir", projectDir.toString]
  args ++ #["--", spawnArgs.cmd] ++ spawnArgs.args

public def mkSpawnArgs (whichSandbox : String) (whichEnvBin projectDir : System.FilePath)
    (spawnArgs : SandboxArgs) : IO IO.Process.SpawnArgs := do
  return {
    cmd := whichEnvBin.toString
    args := #["-i", whichSandbox] ++ buildArgs spawnArgs (← sandboxEnv spawnArgs) projectDir
    cwd := some projectDir
  }

end Lake.Check.Sandbox.Linux
