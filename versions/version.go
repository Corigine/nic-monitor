package versions

import (
	"fmt"
	"runtime"
)

var (
	COMMIT    = "unknown"
	VERSION   = "1.0.0"
	BUILDDATE = "unknown"
)

func String() string {
	return fmt.Sprintf(`
-------------------------------------------------------------------------------
nic-monitor:
  Version:       %v
  Build:         %v
  Commit:        %v
  Go Version:    %v
  Arch:          %v
-------------------------------------------------------------------------------
`, VERSION, BUILDDATE, COMMIT, runtime.Version(), runtime.GOARCH)
}
