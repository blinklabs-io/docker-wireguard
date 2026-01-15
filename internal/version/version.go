// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package version

import (
	"fmt"
)

// These are populated at build time
var (
	Version    string
	CommitHash string
)

func GetVersionString() string {
	version := Version
	if version == "" {
		version = "devel"
	}
	if CommitHash == "" {
		return version
	}
	return fmt.Sprintf("%s (commit %s)", version, CommitHash)
}
