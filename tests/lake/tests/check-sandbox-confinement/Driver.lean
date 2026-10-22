module

import all Lake.Check.Sandbox.Linux
import all Lake.Check.Sandbox.Types
import Lean.Data.Json.Parser
import Lean.Data.Json.FromToJson

/-! Runs behavioral probes through Lake's actual Linux sandbox argument builder. -/

open Lake.Check

structure Request where
  cmd : String
  args : Array String := #[]
  readablePaths : Array System.FilePath
  writablePaths : Array System.FilePath
  env : Array (String × String)
  cwd : System.FilePath
  network : Bool := false
  deriving Lean.FromJson

public def main (args : List String) : IO UInt32 := do
  let [requestFile] := args | throw <| IO.userError "expected a JSON request file"
  let contents ← IO.FS.readFile requestFile
  let request : Request ← IO.ofExcept <| do
    Lean.fromJson? (← Lean.Json.parse contents)
  let spawnArgs ← Sandbox.Linux.mkSpawnArgs "bwrap" "/usr/bin/env" request.cwd {
    cmd := request.cmd
    args := request.args
    readablePaths := request.readablePaths
    writablePaths := request.writablePaths
    envPass := #[]
    envOverride := request.env.map fun (key, value) => (key, some value)
    tmpfsPaths := Sandbox.Linux.forbiddenPaths
    cwd := some request.cwd
    network := request.network
  }
  let child ← IO.Process.spawn spawnArgs
  child.wait
