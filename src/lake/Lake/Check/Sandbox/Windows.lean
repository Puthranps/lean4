/-
Copyright (c) 2026 Lean FRO, LLC. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
module

prelude
public import Lake.Check.Sandbox.Types

namespace Lake.Check.Sandbox.Windows

/-- Rejects requests until native Windows confinement is available. -/
public def mkSpawnArgs (_projectDir : System.FilePath) (_spawnArgs : SandboxArgs) :
    IO IO.Process.SpawnArgs :=
  throw <| IO.userError "Native Windows sandboxing is not implemented."

end Lake.Check.Sandbox.Windows
