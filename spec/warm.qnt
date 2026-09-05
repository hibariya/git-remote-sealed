// Build-time warmup spec: its only job is to make `quint verify` download
// Apalache into the image layer, so model checks run without network.
module warm {
  var x: int
  action init = x' = 0
  action step = x' = x
  val inv = x >= 0
  run warmTest = init.then(step).expect(inv)
}
