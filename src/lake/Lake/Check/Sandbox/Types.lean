/-
Copyright (c) 2025 Lean FRO, LLC. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Henrik Böving
-/
module

prelude
public import Init.System.IO

namespace Lake.Check

public structure SandboxArgs where
  cmd : String
  args : Array String
  envPass : Array String
  envOverride : Array (String × Option String) := #[]
  /-- Bound back read-only over the covered home directories, so the run can still read these. -/
  readablePaths : Array System.FilePath
  writablePaths : Array System.FilePath
  /--
  Linux paths masked with a tmpfs so they exist but do not have the same content as the host
  system.
  -/
  tmpfsPaths : Array System.FilePath
  /-- Whether the child gets a network at all. -/
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

end Lake.Check
