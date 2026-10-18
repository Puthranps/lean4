/-
Copyright (c) 2025 Lean FRO, LLC. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Henrik Böving
-/
module

prelude
public import Init.System.IO
import Init.Data.ToString.Macro

namespace Lake.Check

public inductive SandboxLocation where
  | noSandbox
  | path (path : String)

public structure SandboxArgs where
  cmd : String
  args : Array String
  envPass : Array String
  envOverride : Array (String × Option String) := #[]
  /-- Bound back read-only over the covered home directories, so the run can still read these. -/
  readablePaths : Array System.FilePath
  writablePaths : Array System.FilePath
  /--
  Paths that get masked with a tmpfs so they exist but do not have the same content as the host
  system.
  -/
  tmpfsPaths : Array System.FilePath
  /-- Whether the child gets a network at all. `bwrap` cannot narrow one to particular ports. -/
  network : Bool := false
  /-- Different working directory for the sandboxed process to operate in. -/
  cwd : Option System.FilePath := none

/-- The environment the sandboxed child runs with; `envOverride` wins over `envPass`. -/
public def sandboxEnv (spawnArgs : SandboxArgs) : IO (Array (String × String)) := do
  let mut env := #[]
  for name in spawnArgs.envPass do
    if let some value ← IO.getEnv name then
      env := env.push (name, value)
  for (name, value?) in spawnArgs.envOverride do
    env := env.filter (·.1 != name)
    if let some value := value? then
      env := env.push (name, value)
  return env

/--
Builds the `bwrap` command line.

`/` is bound read-only and the home directories are then covered with a `tmpfs`, so the code being
judged is built against the system it expects while none of the invoking user's files are readable.
Mounts apply in order, so `readablePaths` binds back what the run does need on top of those covers.
Only the paths in `writablePaths` are writable, and the network is a namespace rather than a filter:
a run either has one or has none at all.
-/
public def buildSandboxArgs (spawnArgs : SandboxArgs) (env : Array (String × String))
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

/-- Resolves a sandbox request to a process invocation without loading a Lake workspace. -/
public def Sandbox.mkSpawnArgs (whichSandbox : SandboxLocation)
    (whichEnvBin projectDir : System.FilePath) (spawnArgs : SandboxArgs) :
    IO IO.Process.SpawnArgs := do
  match whichSandbox with
  | .noSandbox =>
    return {
      cmd := spawnArgs.cmd,
      args := spawnArgs.args,
      cwd := some (spawnArgs.cwd.getD projectDir)
      env := spawnArgs.envOverride
    }
  | .path whichSandbox =>
    return {
      cmd := whichEnvBin.toString
      args := #["-i", whichSandbox] ++ buildSandboxArgs spawnArgs (← sandboxEnv spawnArgs) projectDir
      cwd := some projectDir
    }

end Lake.Check
