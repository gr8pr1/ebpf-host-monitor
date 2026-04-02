package mitre

// ChainDetector is the extension point for temporal MITRE ATT&CK kill-chain correlation
// (multi-event sequences, parent spans). Not yet implemented — OTel trace export must
// be stable before correlating spans across the pipeline.
type ChainDetector struct{}

// ProcessWindow is a no-op placeholder for future cross-event state.
func (c *ChainDetector) ProcessWindow() {}
