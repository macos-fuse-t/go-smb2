package stats

import (
	"encoding/json"
	"net/http"
	"sync"
)

type FileStats struct {
	ReadBytes        uint64 `json:"read-bytes"`
	WriteBytes       uint64 `json:"write-bytes"`
	WriteBytesIdent  uint64 `json:"write-bytes-ident"`
	WriteBytesZero   uint64 `json:"write-bytes-zero"`
	DeleteCount      uint64 `json:"delete-count"`
	RenameCount      uint64 `json:"rename-count"`
	TruncateCount    uint64 `json:"truncate-count"`
	OpenCount        uint64 `json:"open-count"`
	XattrListCount   uint64 `json:"xattr-list"`
	XattrReadCount   uint64 `json:"xattr-read"`
	XattrWriteCount  uint64 `json:"xattr-write"`
	XattrDeleteCount uint64 `json:"xattr-delete"`
}

type Stats struct {
	ReadBytes        uint64 `json:"read-bytes"`
	WriteBytes       uint64 `json:"write-bytes"`
	WriteBytesIdent  uint64 `json:"write-bytes-ident"`
	WriteBytesZero   uint64 `json:"write-bytes-zero"`
	OpenCount        uint64 `json:"open-count"`
	DeleteCount      uint64 `json:"delete"`
	RenameCount      uint64 `json:"rename"`
	TruncateCount    uint64 `json:"truncate"`
	MkdirCount       uint64 `json:"mkdir"`
	SymlinkCount     uint64 `json:"symlink"`
	XattrListCount   uint64 `json:"xattr-list"`
	XattrReadCount   uint64 `json:"xattr-read"`
	XattrWriteCount  uint64 `json:"xattr-write"`
	XattrDeleteCount uint64 `json:"xattr-delete"`

	Files map[string]FileStats
}

var (
	// Mutex to protect concurrent access to stats
	statsMutex sync.RWMutex
	stats      = &Stats{Files: make(map[string]FileStats)}
)

func AddReadBytes(name string, cnt uint64) {
	statsMutex.Lock()
	defer statsMutex.Unlock()
	stats.ReadBytes += cnt

	f := stats.Files[name]
	f.ReadBytes += cnt
	stats.Files[name] = f
}

func AddWriteBytes(name string, cnt uint64) {
	statsMutex.Lock()
	defer statsMutex.Unlock()
	stats.WriteBytes += cnt

	f := stats.Files[name]
	f.WriteBytes += cnt
	stats.Files[name] = f
}

func AddWriteIdentBytes(name string, cnt uint64) {
	statsMutex.Lock()
	defer statsMutex.Unlock()
	stats.WriteBytesIdent += cnt

	f := stats.Files[name]
	f.WriteBytesIdent += cnt
	stats.Files[name] = f
}

func AddWriteZeroBytes(name string, cnt uint64) {
	statsMutex.Lock()
	defer statsMutex.Unlock()
	stats.WriteBytesZero += cnt

	f := stats.Files[name]
	f.WriteBytesZero += cnt
	stats.Files[name] = f
}

func AddOpen(name string) {
	statsMutex.Lock()
	defer statsMutex.Unlock()
	stats.OpenCount++

	f := stats.Files[name]
	f.OpenCount++
	stats.Files[name] = f
}

func AddDelete(name string) {
	statsMutex.Lock()
	defer statsMutex.Unlock()
	stats.DeleteCount++

	f := stats.Files[name]
	f.DeleteCount++
	stats.Files[name] = f
}

func AddRename(name string) {
	statsMutex.Lock()
	defer statsMutex.Unlock()
	stats.RenameCount++

	f := stats.Files[name]
	f.RenameCount++
	stats.Files[name] = f
}

func AddTruncate(name string) {
	statsMutex.Lock()
	defer statsMutex.Unlock()
	stats.TruncateCount++

	f := stats.Files[name]
	f.TruncateCount++
	stats.Files[name] = f
}

func AddSymlink(name string) {
	statsMutex.Lock()
	defer statsMutex.Unlock()
	stats.SymlinkCount++
}

func AddMkdir(name string) {
	statsMutex.Lock()
	defer statsMutex.Unlock()
	stats.MkdirCount++
}

func AddXattrList(name string) {
	statsMutex.Lock()
	defer statsMutex.Unlock()
	stats.XattrListCount++

	f := stats.Files[name]
	f.XattrListCount++
	stats.Files[name] = f
}

func AddXattrRead(name string) {
	statsMutex.Lock()
	defer statsMutex.Unlock()
	stats.XattrReadCount++

	f := stats.Files[name]
	f.XattrReadCount++
	stats.Files[name] = f
}

func AddXattrWrite(name string) {
	statsMutex.Lock()
	defer statsMutex.Unlock()
	stats.XattrWriteCount++

	f := stats.Files[name]
	f.XattrWriteCount++
	stats.Files[name] = f
}

func AddXattrDelete(name string) {
	statsMutex.Lock()
	defer statsMutex.Unlock()
	stats.XattrDeleteCount++

	f := stats.Files[name]
	f.XattrDeleteCount++
	stats.Files[name] = f
}

func StatServer(addr string) {
	http.HandleFunc("/", statsHandler)
	http.HandleFunc("/reset", resetHandler)
	http.ListenAndServe(addr, nil)
}

func statsHandler(w http.ResponseWriter, r *http.Request) {
	statsMutex.RLock()
	defer statsMutex.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func resetHandler(w http.ResponseWriter, r *http.Request) {
	// Reset the stats
	statsMutex.Lock()
	stats = &Stats{Files: make(map[string]FileStats)}
	defer statsMutex.Unlock()

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Stats reset successfully!"))
}
