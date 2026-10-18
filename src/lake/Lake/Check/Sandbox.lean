/-
Copyright (c) 2025 Lean FRO, LLC. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Henrik Böving
-/
module

prelude
public import Lake.Check.Sandbox.Types
public import Lake.Check.Sandbox.Linux
public import Lake.Check.Sandbox.Windows

namespace Lake.Check

public inductive SandboxLocation where
  | noSandbox
  | linux (path : String)
  | windows

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
  | .linux whichSandbox =>
    Sandbox.Linux.mkSpawnArgs whichSandbox whichEnvBin projectDir spawnArgs
  | .windows =>
    Sandbox.Windows.mkSpawnArgs projectDir spawnArgs

end Lake.Check
