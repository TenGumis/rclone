package restserver

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/miolini/datacounter"
	"github.com/ncw/rclone/fs"
	"github.com/ncw/rclone/fs/list"
	"github.com/ncw/rclone/fs/operations"
	"github.com/prometheus/client_golang/prometheus"
	"goji.io/middleware"
	"goji.io/pat"
)

func isHashed(dir string) bool {
	return dir == "data"
}

var validTypes = []string{"data", "index", "keys", "locks", "snapshots", "config"}

func isValidType(name string) bool {
	for _, tpe := range validTypes {
		if name == tpe {
			return true
		}
	}

	return false
}

// getRepo returns the repository location, relative to Config.Path.
func getRepo(r *http.Request) string {
	if strings.HasPrefix(fmt.Sprintf("%s", middleware.Pattern(r.Context())), "/:repo") {
		return pat.Param(r, "repo")
	}
	return "."
}

// getRemote returns the remote for a file type in the repo.
func getRemote(r *http.Request, fileType string) (string, error) {
	if !isValidType(fileType) {
		return "", errors.New("invalid file type")
	}
	return path.Join(getRepo(r), fileType), nil
}

// getFileRemote returns the remote for a file in the repo.
func getFileRemote(r *http.Request, fileType, name string) (string, error) {
	if !isValidType(fileType) {
		return "", errors.New("invalid file type")
	}

	if isHashed(fileType) {
		if len(name) < 2 {
			return "", errors.New("file name is too short")
		}

		return path.Join(getRepo(r), fileType, name[:2], name), nil
	}

	return path.Join(getRepo(r), fileType, name), nil
}

// getUser returns the username from the request, or an empty string if none.
func getUser(r *http.Request) string {
	username, _, ok := r.BasicAuth()
	if !ok {
		return ""
	}
	return username
}

// getMetricLabels returns the prometheus labels from the request.
func getMetricLabels(r *http.Request) prometheus.Labels {
	labels := prometheus.Labels{
		"user": getUser(r),
		"repo": getRepo(r),
		"type": pat.Param(r, "type"),
	}
	return labels
}

// AuthHandler wraps h with a http.HandlerFunc that performs basic authentication against the user/passwords pairs
// stored in f and returns the http.HandlerFunc.
func AuthHandler(f *HtpasswdFile, h http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if username, password, ok := r.BasicAuth(); !ok || !f.Validate(username, password) {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		h.ServeHTTP(w, r)
	}
}

// head request the remote
func headRequest(w http.ResponseWriter, r *http.Request, remote string) {
	o, err := Config.FS.NewObject(remote)
	if err != nil {
		if Config.Debug {
			log.Print(err)
		}
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}

	// Set content length since we know how long the object is
	w.Header().Set("Content-Length", strconv.FormatInt(o.Size(), 10))
}

// get the remote
func getRequest(w http.ResponseWriter, r *http.Request, remote string) {
	blob, err := Config.FS.NewObject(remote)
	if err != nil {
		if Config.Debug {
			log.Print(err)
		}
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}

	// Set content length since we know how long the object is
	w.Header().Set("Content-Length", strconv.FormatInt(blob.Size(), 10))

	// Decode Range request if present
	code := http.StatusOK
	size := blob.Size()
	var options []fs.OpenOption
	if rangeRequest := r.Header.Get("Range"); rangeRequest != "" {
		//fs.Debugf(nil, "Range: request %q", rangeRequest)
		option, err := fs.ParseRangeOption(rangeRequest)
		if err != nil {
			if Config.Debug {
				log.Print(err)
			}
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		options = append(options, option)
		offset, limit := option.Decode(blob.Size())
		end := blob.Size() // exclusive
		if limit >= 0 {
			end = offset + limit
		}
		if end > blob.Size() {
			end = blob.Size()
		}
		size = end - offset
		// fs.Debugf(nil, "Range: offset=%d, limit=%d, end=%d, size=%d (object size %d)", offset, limit, end, size, blob.Size())
		// Content-Range: bytes 0-1023/146515
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", offset, end-1, blob.Size()))
		// fs.Debugf(nil, "Range: Content-Range: %q", w.Header().Get("Content-Range"))
		code = http.StatusPartialContent
	}
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))

	file, err := blob.Open(options...)
	if err != nil {
		if Config.Debug {
			log.Print(err)
		}
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}
	defer func() {
		err := file.Close()
		if err != nil {
			log.Print(err)
		}
	}()

	w.WriteHeader(code)

	wc := datacounter.NewResponseWriterCounter(w)
	_, err = io.Copy(wc, file)
	if err != nil {
		if Config.Debug {
			log.Print(err)
		}
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	if Config.Prometheus {
		labels := getMetricLabels(r)
		metricBlobReadTotal.With(labels).Inc()
		metricBlobReadBytesTotal.With(labels).Add(float64(wc.Count()))
	}
}

// saveRequest saves a request to the repository.
func saveRequest(w http.ResponseWriter, r *http.Request, remote string) {
	// The object mustn't already exist
	o, err := Config.FS.NewObject(remote)
	if err == nil {
		http.Error(w, http.StatusText(http.StatusConflict), http.StatusConflict)
		return
	}

	o, err = operations.Rcat(Config.FS, remote, r.Body, time.Now())
	if err != nil {
		if Config.Debug {
			log.Print(err)
		}
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	if Config.Prometheus {
		labels := getMetricLabels(r)
		metricBlobWriteTotal.With(labels).Inc()
		metricBlobWriteBytesTotal.With(labels).Add(float64(o.Size()))
	}
}

// delete the remote
func deleteRequest(w http.ResponseWriter, r *http.Request, remote string) {
	o, err := Config.FS.NewObject(remote)
	if err != nil {
		if Config.Debug {
			log.Print(err)
		}
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}

	if err := o.Remove(); err != nil {
		fs.Errorf(remote, "Delete error: %v", err)
		if Config.Debug {
			log.Print(err)
		}
		if err == fs.ErrorObjectNotFound {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		} else {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}
		return
	}

	if Config.Prometheus {
		labels := getMetricLabels(r)
		metricBlobDeleteTotal.With(labels).Inc()
		metricBlobDeleteBytesTotal.With(labels).Add(float64(o.Size()))
	}
}

// CheckConfig checks whether a configuration exists.
func CheckConfig(w http.ResponseWriter, r *http.Request) {
	if Config.Debug {
		log.Println("CheckConfig()")
	}
	remote, err := getRemote(r, "config")
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	headRequest(w, r, remote)
}

// GetConfig allows for a config to be retrieved.
func GetConfig(w http.ResponseWriter, r *http.Request) {
	if Config.Debug {
		log.Println("GetConfig()")
	}
	remote, err := getRemote(r, "config")
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	getRequest(w, r, remote)
}

// SaveConfig allows for a config to be saved.
func SaveConfig(w http.ResponseWriter, r *http.Request) {
	if Config.Debug {
		log.Println("SaveConfig()")
	}
	remote, err := getRemote(r, "config")
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	saveRequest(w, r, remote)
}

// DeleteConfig removes a config.
func DeleteConfig(w http.ResponseWriter, r *http.Request) {
	if Config.Debug {
		log.Println("DeleteConfig()")
	}

	if Config.AppendOnly {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}

	remote, err := getRemote(r, "config")
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	deleteRequest(w, r, remote)
}

// listItem is an element returned for the restic v2 list response
type listItem struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
}

// return type for list
type listItems []listItem

// add a DirEntry to the listItems
func (ls *listItems) add(entry fs.DirEntry) {
	if o, ok := entry.(fs.Object); ok {
		*ls = append(*ls, listItem{
			Name: path.Base(o.Remote()),
			Size: o.Size(),
		})
	}
}

// ListBlobs lists all blobs of a given type in an arbitrary order.
func ListBlobs(w http.ResponseWriter, r *http.Request) {
	if Config.Debug {
		log.Println("ListBlobs()")
	}
	fileType := pat.Param(r, "type")
	dir, err := getRemote(r, fileType)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// FIXME it might be better to replace this with a directory recursion
	// err := walk.Walk(Config.FS, dir, true, -1, func(path string, entries fs.DirEntries, err error) error { })

	items, err := list.DirSorted(Config.FS, true, dir)
	fs.Debugf(dir, "items = %v", items)
	if err != nil {
		if Config.Debug {
			log.Print(err)
		}
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}

	var ls listItems
	for _, i := range items {
		if isHashed(fileType) {
			subpath := i.Remote()
			var subitems fs.DirEntries
			subitems, err = list.DirSorted(Config.FS, true, subpath)
			fs.Debugf(subpath, "subitems = %v", subitems)
			if err != nil {
				if Config.Debug {
					log.Print(err)
				}
				http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
				return
			}
			for _, item := range subitems {
				ls.add(item)
			}
		} else {
			ls.add(i)
		}
	}

	data, err := json.Marshal(ls)
	if err != nil {
		if Config.Debug {
			log.Print(err)
		}
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	fs.Debugf(dir, "ls = %v", ls)
	w.Header().Set("Content-Type", "application/vnd.x.restic.rest.v2")

	_, _ = w.Write(data)
}

// CheckBlob tests whether a blob exists.
func CheckBlob(w http.ResponseWriter, r *http.Request) {
	if Config.Debug {
		log.Println("CheckBlob()")
	}

	remote, err := getFileRemote(r, pat.Param(r, "type"), pat.Param(r, "name"))
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	headRequest(w, r, remote)
}

// GetBlob retrieves a blob from the repository.
func GetBlob(w http.ResponseWriter, r *http.Request) {
	if Config.Debug {
		log.Println("GetBlob()")
	}

	remote, err := getFileRemote(r, pat.Param(r, "type"), pat.Param(r, "name"))
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	getRequest(w, r, remote)
}

// SaveBlob saves a blob to the repository.
func SaveBlob(w http.ResponseWriter, r *http.Request) {
	if Config.Debug {
		log.Println("SaveBlob()")
	}

	remote, err := getFileRemote(r, pat.Param(r, "type"), pat.Param(r, "name"))
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	saveRequest(w, r, remote)
}

// DeleteBlob deletes a blob from the repository.
func DeleteBlob(w http.ResponseWriter, r *http.Request) {
	if Config.Debug {
		log.Println("DeleteBlob()")
	}

	if Config.AppendOnly && pat.Param(r, "type") != "locks" {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}

	remote, err := getFileRemote(r, pat.Param(r, "type"), pat.Param(r, "name"))
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	deleteRequest(w, r, remote)
}

// CreateRepo creates repository directories.
func CreateRepo(w http.ResponseWriter, r *http.Request) {
	if Config.Debug {
		log.Println("CreateRepo()")
	}

	repo := getRepo(r)

	if r.URL.Query().Get("create") != "true" {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	log.Printf("Creating repository directories in %s\n", repo)

	if err := Config.FS.Mkdir(repo); err != nil {
		log.Print(err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	for _, d := range validTypes {
		if d == "config" {
			continue
		}

		if err := Config.FS.Mkdir(path.Join(repo, d)); err != nil {
			log.Print(err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	}

	for i := 0; i < 256; i++ {
		if err := Config.FS.Mkdir(path.Join(repo, "data", fmt.Sprintf("%02x", i))); err != nil {
			log.Print(err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	}
}
