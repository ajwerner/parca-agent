// Copyright (c) 2022 The Parca Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package debuginfo

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/goburrow/cache"

	"github.com/parca-dev/parca-agent/pkg/objectfile"
)

type realfs struct{}

func (f *realfs) Open(name string) (fs.File, error) { return os.Open(name) }

var fileSystem fs.FS = &realfs{}

// Finder finds the separate debug information files on the system.
type Finder struct {
	logger log.Logger

	cache     cache.Cache
	debugDirs []string
}

var defaultDebugDirs = []string{"/usr/lib/debug"}

// NewFinder creates a new Finder.
func NewFinder(logger log.Logger) *Finder {
	// TODO(kakkoyun): Add the ability to specify the global debug directories as CLI arguments.
	debugDirs := defaultDebugDirs
	return &Finder{
		logger:    log.With(logger, "component", "finder"),
		cache:     cache.New(cache.WithMaximumSize(128)), // Arbitrary cache size.
		debugDirs: debugDirs,
	}
}

// Find finds the separate debug file for the given object file.
func (f *Finder) Find(ctx context.Context, objFile *objectfile.MappedObjectFile) (string, error) {
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	default:
	}

	buildID := objFile.BuildID
	root := objFile.Root()
	path := objFile.Path

	if val, ok := f.cache.GetIfPresent(buildID); ok {
		switch v := val.(type) {
		case string:
			return v, nil
		case error:
			return "", v
		default:
			// We didn't put you there?!
			return "", errors.New("unexpected type")
		}
	}

	file, err := f.find(root, buildID, path)
	if err != nil {
		if errors.Is(err, errNotFound) {
			f.cache.Put(buildID, err)
			return "", err
		}
	}

	f.cache.Put(buildID, file)
	return file, nil
}

func (f *Finder) find(root, buildID, path string) (string, error) {
	if len(buildID) < 2 {
		return "", errors.New("invalid build ID")
	}

	// TODO(kakkoyun): Check for .gnu_debuglink to determine filename.
	// There are two ways of specifying the separate debug info file:
	// 1) The executable contains a debug link that specifies the name of the separate debug info file.
	//	The separate debug file’s name is usually executable.debug,
	//	where executable is the name of the corresponding executable file without leading directories (e.g., ls.debug for /usr/bin/ls).
	// 2) The executable contains a build ID, a unique bit string that is also present in the corresponding debug info file.
	//  (This is supported only on some operating systems, when using the ELF or PE file formats for binary files and the GNU Binutils.)
	//  The debug info file’s name is not specified explicitly by the build ID, but can be computed from the build ID, see below.
	//
	// So, for example, suppose you ask Agent to debug /usr/bin/ls, which has a debug link that specifies the file ls.debug,
	//	and a build ID whose value in hex is abcdef1234.
	//	If the list of the global debug directories includes /usr/lib/debug (which is the default),
	//	then Finder will look for the following debug information files, in the indicated order:
	//
	//		- /usr/lib/debug/.build-id/ab/cdef1234.debug
	//		- /usr/bin/ls.debug
	//		- /usr/bin/.debug/ls.debug
	//		- /usr/lib/debug/usr/bin/ls.debug
	//
	// For further information, see: https://sourceware.org/gdb/onlinedocs/gdb/Separate-Debug-Files.html
	files := f.generatePaths(root, buildID, path)
	if len(files) == 0 {
		return "", errors.New("failed to generate paths")
	}

	// TODO(kakkoyun): Remove logs.
	for _, file := range files {
		logger := log.With(f.logger, "path", path, "debugfile", file, "buildID", buildID)
		level.Debug(logger).Log("msg", "looking for separate debug file")
		_, err := fs.Stat(fileSystem, file)
		if err == nil {
			level.Debug(logger).Log("msg", "found separate debug file")
			return file, nil
		}

		level.Debug(logger).Log("msg", "not found separate debug file", "err", err)
		fmt.Println(err)
		if os.IsNotExist(err) {
			continue
		}

		level.Warn(logger).Log("msg", "failed to search separate debug file", "err", err)
	}

	return "", errNotFound
}

func (f *Finder) generatePaths(root, buildID, path string) []string {
	var files []string
	for _, dir := range f.debugDirs {
		rel, err := filepath.Rel(root, path)
		if err != nil {
			continue
		}
		files = append(files, []string{
			filepath.Join(root, dir, ".build-id", buildID[:2], buildID[2:]) + ".debug",
			path + ".debug",
			filepath.Join(filepath.Dir(path), ".debug", filepath.Base(path)) + ".debug",
			filepath.Join(root, dir, rel) + ".debug",
		}...)
	}
	return files
}
