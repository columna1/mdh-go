package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"flag"
	"io"
	"io/ioutil"
	"log"
	"math"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/pprof"
	"strconv"
	"strings"
	"sync"
	"time"

	badger "github.com/dgraph-io/badger/v2"
	"github.com/dgraph-io/badger/v2/options"
	"golang.org/x/crypto/nacl/box"
)

var cpuprofile = flag.String("cpuprofile", "", "write cpu profile to a `file`")
var logFile = flag.String("logFile", "", "`File` to write logs to")
var memprofile = flag.String("memprofile", "", "write memory profile to `file`")

type currentCertificate struct {
	sync.Mutex
	certificate *tls.Certificate
}

type configuration struct {
	ClientSecret                string
	ClientHostname              string
	ClientPort                  int
	GracefulShutdownWaitSeconds int
	MaxCacheSizeInMebibytes     int
	MaxKilobitsPerSecond        int
	MaxMebibytesPerHour         int
	ServerEndpoint              string
}
type pingData struct {
	Secret       string    `json:"secret"`
	Port         int       `json:"port"`
	DiskSpace    int       `json:"disk_space"`
	NetworkSpeed int       `json:"network_speed"`
	BuildVersion int       `json:"build_version"`
	TLSCreatedAt time.Time `json:"tls_created_at,omitempty"`
}
type serverReply struct {
	ImageServer string `json:"image_server"`
	URL         string `json:"url"`
	Compromised bool   `json:"compromised"`
	LatestBuild int    `json:"latest_build"`
	TokenKey    string `json:"token_key"`
	Paused      bool   `json:"paused"`
	TLS         struct {
		CreatedAt   time.Time `json:"created_at"`
		PrivateKey  string    `json:"private_key"`
		Certificate string    `json:"certificate"`
	} `json:"tls"`
}
type keyValue struct {
	ContentType  string `json:"Content_Type"`
	LastAccessed int64  `json:"last_accessed"`
	FileSize     int64  `json:"file_size"`
	LastModified string `json:"last_modified"`
}
type tokenData struct {
	Expires time.Time `json:"expires"`
	Hash    string    `json:"hash"`
}

//file structure will be
//cache/data/ff/ff/ff/ffffffaaaaaa/file.1
//cache/data-saver/ff/ff/ff/ffffffaaaaaaaa/file.2

var settings configuration
var reply serverReply
var version = 16
var clientVersion = "1.0.0"
var exeDir string

const (
	dirPermissions                      = 0777 // permissive for directory
	filePermissions         os.FileMode = 0666 // permissive for files
	sensitiveFilePermission os.FileMode = 0600 // only owner can read sensitive data
)

var cacheDir = "cache"

//var serverAPIAddress = "https://mangadex-test.net/"

var serverAPIAddress = "https://api.mangadex.network/"

var db *badger.DB
var running bool
var diskUsed uint64
var lastRequest time.Time
var timeOfStop time.Time
var lastPing time.Time
var settingModTime time.Time
var currentTLSModTime time.Time
var rgx *regexp.Regexp

func getFilePath(words []string) string {
	r1 := rgx.FindAllSubmatch([]byte(words[2]), -1)
	fn := ""
	if r1 != nil {
		v := r1[0]
		fn = string(v[1]) + string(v[3])
		if len(fn) < 3 {
			fn = words[2]
		}
	} else {
		fn = words[2]
	}
	return exeDir + "/" + cacheDir + "/" + words[0] + "/" + words[1][0:2] + "/" + words[1][2:4] + "/" + words[1][4:6] + "/" + words[1] + "/" + fn
}
func getFileDir(words []string) string {
	return exeDir + "/" + cacheDir + "/" + words[0] + "/" + words[1][0:2] + "/" + words[1][2:4] + "/" + words[1][4:6] + "/" + words[1]
}
func getFileDirFromBytes(id []byte) string {
	is := string(id)
	words := strings.Split(is, "/")
	return exeDir + "/" + cacheDir + "/" + words[0] + "/" + words[1][0:2] + "/" + words[1][2:4] + "/" + words[1][4:6] + "/" + words[1]
}
func getFilePathFromBytes(id []byte) string {
	is := string(id)
	words := strings.Split(is, "/")
	r1 := rgx.FindAllSubmatch([]byte(words[2]), -1)
	fn := ""
	if r1 != nil {
		v := r1[0]
		fn = string(v[1]) + string(v[3])
		if len(fn) < 3 {
			fn = words[2]
		}
	} else {
		fn = words[2]
	}
	return exeDir + "/" + cacheDir + "/" + words[0] + "/" + words[1][0:2] + "/" + words[1][2:4] + "/" + words[1][4:6] + "/" + words[1] + "/" + fn
}

func checkForFile(words []string) (exists bool) {
	//urls will look like /data/aaf33f3f33f3ff35abaf/m2.png
	filePath := getFilePath(words)
	if _, err := os.Stat(filePath); err == nil {
		exists = true
	} else if os.IsNotExist(err) {
		exists = false
	}
	return
}

func textColor(str string, color uint8) string {
	return string(0x1b) + "[" + strconv.Itoa(int(color)) + "m" + str + string(0x1b) + "[37m"
}

func logNoFatal(err error) {
	if err != nil {
		log.Println(textColor("Error: "+err.Error(), 31))
	}
}

func grabRandomKey() string { //grabs a random key by iterating over the cache dir in a random fashion
	name := ""
	fname := exeDir + "/" + cacheDir
	kname := ""
	n := 0
	for {
		n++
		f, err := os.Open(fname)
		if err != nil {
			log.Fatal(err)
		}
		files, err := f.Readdir(-1)
		f.Close()
		if err != nil {
			log.Fatal(err)
		}
		//fmt.Println(len(files))
		if len(files) <= 0 {
			break
		}
		r := rand.Intn(len(files))
		//fmt.Println(r, files[r].Name())
		name = files[r].Name()
		fname += "/" + name
		if n == 1 || n > 4 { //TODO: magic numbers
			kname += "/" + name
		}
		if !files[r].IsDir() {
			break
		}
	}
	//fmt.Println(name)
	return kname[1:]
}

func evictCache() { //just removes something from cache
	beforeDiskuse := diskUsed
	// The following code generates 10 random keys
	lowestNum := int64(math.MaxInt64)
	var lowestKey []byte
	var lowestNumSize int64
	for i := 0; i < 10; i++ {
		key := []byte(grabRandomKey())
		//log.Println("got random key #", i)
		// Pick a random key from the list of keys
		//fmt.Printf("%s\n", key)

		err := db.View(func(txn *badger.Txn) error {
			item, err := txn.Get(key)
			if err != nil {
				log.Println("error badger get: ", err)
				return err
			}
			err = item.Value(func(val []byte) error {
				var entry keyValue
				json.Unmarshal(val, &entry)
				if entry.LastAccessed < lowestNum {
					lowestKey = key
					lowestNum = entry.LastAccessed
					lowestNumSize = entry.FileSize
				}
				return nil
			})
			return err
		})
		if err != nil {
			log.Println("error badger view: ", err)
			return
		}
	}
	//delete chapter of lowest key and update diskuse
	path := getFileDirFromBytes(lowestKey)
	//log.Println(lowestKey, path)
	f, err := os.Open(path)
	if err != nil {
		logNoFatal(err)
		return
	}
	d, err := f.Readdir(-1)
	if err != nil {
		logNoFatal(err)
		return
	}
	wds := strings.Split(string(lowestKey), "/")
	keypath := wds[0] + "/" + wds[1]
	du := uint64(settings.MaxCacheSizeInMebibytes) * 1024 * 1024
	dif := uint64(diskUsed - du)
	log.Println(textColor("Disk usage gone over by "+strconv.FormatUint(dif, 10)+" bytes", 33))
	log.Println(textColor("removing chapter "+keypath, 33))
	for i := 0; i < len(d); i++ {
		err = db.Update(func(txn *badger.Txn) error {
			//delete key
			//log.Println("deleted " + path + "/" + d[i].Name())
			err := os.Remove(path + "/" + d[i].Name())
			logNoFatal(err)
			err = txn.Delete([]byte(keypath + "/" + d[i].Name()))
			//log.Println(keypath + "/" + d[i].Name())
			return err
		})
		if err != nil {
			log.Println("error badger: ", err)
		} else {
			updateTotalDiskUse(0 - int(lowestNumSize))
		}
	}
	os.Remove(path)
	log.Println(textColor("removed "+strconv.FormatUint(beforeDiskuse-diskUsed, 10)+" bytes", 33))
}

func updateTotalDiskUse(bytes int) {
	//log.Println("updating Disk use")
	//log.Println(bytes)
	err := db.Update(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte("totalDiskUsed"))
		if err != nil && err.Error() == "Key not found" {
			log.Println("Disk usage stat not found, creating it. Using " + strconv.Itoa(bytes) + " bytes")
			v := make([]byte, 8)
			binary.LittleEndian.PutUint64(v, uint64(bytes))
			diskUsed = uint64(bytes)
			err := txn.Set([]byte("totalDiskUsed"), v)
			logNoFatal(err)
			return nil
		} else if err != nil {
			return err
		}
		err = item.Value(func(val []byte) error {

			in := binary.LittleEndian.Uint64(val)
			if bytes < 0 {
				in -= uint64(math.Abs(float64(bytes)))
			} else {
				in += uint64(bytes)
			}
			//log.Println("Disk used is now " + strconv.FormatUint(in, 10) + " bytes")
			diskUsed = in
			v := make([]byte, 8)
			binary.LittleEndian.PutUint64(v, in)
			err := txn.Set([]byte("totalDiskUsed"), v)
			logNoFatal(err)
			return nil
		})
		logNoFatal(err)

		return err
	})
	if err != nil {
		log.Println("error disk usage badger: ", err)
	}
}

func handleCacheHit(w http.ResponseWriter, r *http.Request, words []string) {
	//cache hit
	if r.Header.Get("If-Modified-Since") != "" {
		log.Println("Browser cached for " + r.URL.Path + " sending 304")
		w.WriteHeader(http.StatusNotModified)
		return
	}
	st := time.Now()
	contentType := ""
	lm := ""
	id := words[0] + "/" + words[1] + "/" + words[2]
	log.Println(textColor("Cache hit for "+id, 36))
	err := db.Update(func(txn *badger.Txn) error {
		//log.Println(id)
		item, err := txn.Get([]byte(id))
		logNoFatal(err)
		if err != nil {
			return err
		}
		err = item.Value(func(val []byte) error {
			// This func with val would only be called if item.Value encounters no error.

			// Accessing val here is valid.
			var entry keyValue
			json.Unmarshal(val, &entry)
			contentType = entry.ContentType
			lm = entry.LastModified
			v, _ := json.Marshal(entry)
			txn.Set([]byte(id), v)
			entry.LastAccessed = time.Now().Unix()

			json, _ := json.Marshal(entry)
			err := txn.Set([]byte(id), json)
			logNoFatal(err)
			return nil
		})
		logNoFatal(err)

		return err
	})
	if err != nil {
		log.Println("badger err: ", err)
		if err.Error() == "Key not found" {
			log.Println("trying to add db key")
			//Key does not exist in database, attempt to rebuild
			ct := ""
			if strings.ContainsAny(id, ".png") {
				ct = "image/png"
			} else if strings.ContainsAny(id, ".jpg") {
				ct = "image/jpg"
			} else if strings.ContainsAny(id, ".gif") {
				ct = "image/gif"
			}
			st, err := os.Stat(getFilePath(words))
			tn := ""
			var tb int64
			if err != nil {
				logNoFatal(err)
				tn = time.Now().Format(time.RFC1123)
			} else {
				tn = st.ModTime().Format(time.RFC1123)
				tb = st.Size()
				updateTotalDiskUse(int(tb))
			}

			err = db.Update(func(txn *badger.Txn) error {
				t := keyValue{
					ContentType:  ct,
					LastAccessed: time.Now().Unix(),
					LastModified: tn,
					FileSize:     tb, //this can end up as 0, hopefully this never happens (not that it really matters)
				}
				json, _ := json.Marshal(t)
				err := txn.Set([]byte(id), json)
				return err
			})
			if err != nil {
				log.Println("badger update err while rebuilding: ", err)
			}
		}
	}
	if contentType != "" {
		w.Header().Set("Content-Type", contentType)
	}
	if lm != "" {
		w.Header().Set("Last-Modified", lm)
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Access-Control-Allow-Origin", "https://mangadex.org")
	w.Header().Set("Access-Control-Expose-Headers", "*")
	w.Header().Set("Timing-Allow-Origin", "https://mangadex.org")
	w.Header().Set("X-Time-Taken", strconv.Itoa(int(time.Since(st).Milliseconds())))
	w.Header().Set("Cache-Control", "public, max-age=1209600")
	w.Header().Set("X-URI", "/"+id)
	w.Header().Set("connection", "keep-alive")
	w.Header().Set("X-Cache", "HIT")

	http.ServeFile(w, r, getFilePath(words))
	//w.WriteHeader(http.StatusOK)
	log.Print(textColor("Done serving "+id+" in "+strconv.Itoa(int(time.Since(st).Milliseconds()))+"ms", 36))
	//r.Close = true
}

func handleCacheMiss(w http.ResponseWriter, r *http.Request, words []string) {
	st := time.Now()
	id := words[0] + "/" + words[1] + "/" + words[2]
	log.Println(textColor("Cache miss for "+id, 35))
	resp, err := http.Get(reply.ImageServer + "/" + words[0] + "/" + words[1] + "/" + words[2])
	if err != nil {
		//error occurred on the connection to upstream
		log.Println("Error: failed to get image from upstream")
		handleServerError(w, r, err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		//fail and send a 404 response back to the client
		log.Println("upstream is not ok")
		handleNotFound(w, r)
		return
	}
	ct := resp.Header.Get("Content-Type")
	cl := resp.Header.Get("Content-Length")
	lmt := resp.Header.Get("Last-Modified")
	//log.Println(lmt)
	if ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	if lmt != "" {
		w.Header().Set("Last-Modified", lmt)
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Access-Control-Allow-Origin", "https://mangadex.org")
	w.Header().Set("Access-Control-Expose-Headers", "*")
	w.Header().Set("Timing-Allow-Origin", "https://mangadex.org")
	w.Header().Set("X-Time-Taken", strconv.Itoa(int(time.Since(st).Milliseconds())))
	w.Header().Set("X-Cache", "MISS")
	w.Header().Set("Cache-Control", "public, max-age=1209600")
	w.Header().Set("X-URI", "/"+id)
	w.Header().Set("Content-Length", cl)
	w.Header().Set("connection", "keep-alive")

	dir := getFileDir(words)
	fileerr := os.MkdirAll(dir, dirPermissions)
	var f *os.File
	var filebuffWriter *bufio.Writer

	if err != nil {
		log.Println("Error: Could not create directory for file: ", err)
	} else {
		fn := getFilePath(words)
		// If file already exist do not open it (avoid writing it multiple times)
		f, fileerr = os.OpenFile(fn, os.O_CREATE|os.O_EXCL|os.O_RDWR, filePermissions)
		if fileerr != nil {
			log.Println("Error: Could not open file to write: ", fileerr)
		} else {
			filebuffWriter = bufio.NewWriterSize(f, 64000)
		}
	}
	httpbuffWriter := bufio.NewWriterSize(w, 64000)
	var teeUpstreamToClient = io.TeeReader(resp.Body, httpbuffWriter)
	buf := make([]byte, 64000) //one megabyte
	tb := 0
	for {
		n, err := teeUpstreamToClient.Read(buf)
		if fileerr == nil {
			_, fileerr = filebuffWriter.Write(buf[:n])
			if fileerr != nil {
				filebuffWriter.Flush()
				f.Close()
				err = os.Remove(getFilePath(words))
				logNoFatal(err)
				filebuffWriter = nil
			}
		}
		tb += n
		if err == io.EOF {
			break
		} else if err != nil {
			//we got an actual error
			log.Println("an error occurred when transfering image ", id)
			//We can try to send an error 500, if w has already been written to by httpbuffWriter nothing will happen
			handleServerError(w, r, err)
			httpbuffWriter.Flush()
			if filebuffWriter != nil {
				filebuffWriter.Flush()
				f.Close()
				err = os.Remove(getFilePath(words))
				logNoFatal(err)
			}
			return
		}
	}
	if fileerr == nil {
		filebuffWriter.Flush()
		f.Close()
	}
	httpbuffWriter.Flush()
	//w.WriteHeader(http.StatusOK)

	log.Println("Got file from upstream in " + strconv.Itoa(int(time.Since(st).Milliseconds())) + "ms")

	//if we couldn't wite a file maybe we should skip the db entry but it doesn't hurt as
	//it's not used for cache hit lookup
	err = db.Update(func(txn *badger.Txn) error {
		t := keyValue{
			ContentType:  ct,
			LastAccessed: time.Now().Unix(),
			LastModified: lmt,
			FileSize:     int64(tb),
		}
		json, _ := json.Marshal(t)
		err := txn.Set([]byte(id), json)
		return err
	})
	if err != nil {
		log.Println("badger update error: ", err)
	}
	log.Println(textColor("Done serving "+id+" in "+strconv.Itoa(int(time.Since(st).Milliseconds()))+"ms", 35))
	updateTotalDiskUse(tb)
	//r.Close = true
}

func handleNotFound(w http.ResponseWriter, r *http.Request) {
	log.Print(textColor("request not found: "+r.URL.String(), 33)) //yellow color
	w.WriteHeader(http.StatusNotFound)
}

func handleServerError(w http.ResponseWriter, r *http.Request, err error) {
	log.Print(textColor("server error for: "+r.URL.String()+" err: "+err.Error(), 31))
	w.WriteHeader(http.StatusInternalServerError)
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	//before we do anything else, check the referer header, return 403 if it doesn't exist or isn't "https://mangadex.org"
	ref := r.Header.Get("Referer")
	if !strings.HasPrefix(ref, "https://mangadex.org") {
		//log.Println("referer not mangadex", ref, r.Header.Get("User-Agent"))
		//w.WriteHeader(http.StatusForbidden)// this is not enforced yet
		//return
	}
	// Common header
	w.Header().Set("Server", "Mangadex@Home Node github.com/columna1/mdh-go ("+strconv.Itoa(version)+")")
	words := strings.Split(r.URL.Path, "/")
	indOffset := 0
	for i := 0; i < len(words); i++ {
		if words[i] == "data" || words[i] == "data-saver" {
			indOffset = i
			break
		}
	}

	//token exists try to decrypt and validate
	if indOffset == 2 {
		token, err := base64.RawURLEncoding.DecodeString(words[1])
		if err != nil {
			logNoFatal(err)
		}
		keybuf, err := base64.StdEncoding.DecodeString(reply.TokenKey)
		if err != nil {
			logNoFatal(err)
		}
		var decryptNonce [24]byte
		var key [32]byte
		copy(decryptNonce[:], token[:24])
		copy(key[:], keybuf[:32])
		dat, ok := box.OpenAfterPrecomputation(nil, token[24:], &decryptNonce, &key)
		if !ok {
			log.Println("Failed to decrypt token")
			w.WriteHeader(http.StatusForbidden) //403
			return
		}
		tok := tokenData{}
		if err := json.Unmarshal(dat, &tok); err != nil {
			log.Println("failed to decode token json ", err)
		}
		if err != nil {
			log.Println("couldn't parse date from token")
		}
		if time.Now().After(tok.Expires) {
			//Token has expired return 403
			log.Println("Token has expired")
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if tok.Hash != words[indOffset+1] {
			//hashes do not match return 410
			log.Println("token's hash does not match")
			log.Println(words[indOffset+1], "vs", tok.Hash)
			w.WriteHeader(http.StatusGone)
			return
		}
	}
	lastRequest = time.Now()
	//TODO: check to see if file exists under a different name(example: new url format for an old file.)
	//this isn't critical as when/if old files update on the backend, the client will re download and
	//the old ones will get deleted eventually
	if (words[indOffset] == "data" || words[indOffset] == "data-saver") && len(words) > indOffset+2 {
		// Sane URL check
		if len(words[indOffset+1]) < 6 {
			log.Println(words, " ", "chapter length is too small")
			handleNotFound(w, r)
		} else if checkForFile(words[indOffset : indOffset+3]) {
			handleCacheHit(w, r, words[indOffset:indOffset+3])
		} else {
			//cache miss
			//get file and serve it to disk and to reader
			handleCacheMiss(w, r, words[indOffset:indOffset+3])
		}
	} else if r.URL.String() == "/stop" {

		//for debug use
		if serverAPIAddress == "https://mangadex-test.net/" {
			running = false
			w.Write([]byte("Shutting server down!"))
			timeOfStop = time.Now()
		} else {
			handleNotFound(w, r)
		}
	} else if r.URL.String() == "/stat" {
		err := db.Update(func(txn *badger.Txn) error {
			item, err := txn.Get([]byte("totalDiskUsed"))
			err = item.Value(func(val []byte) error {

				in := binary.LittleEndian.Uint64(val)
				w.Write([]byte(strconv.FormatInt(int64(in), 10)))
				return nil
			})
			logNoFatal(err)

			return err
		})
		if err != nil {
			log.Println("error disk usage badger: ", err)
		}
	} else {
		//error
		log.Println(words, indOffset, len(words))
		handleNotFound(w, r)
	}
}

var cCert = &currentCertificate{}

func (c *currentCertificate) loadCertificate(cert, key []byte) error {
	c.Lock()
	defer c.Unlock()

	certAndKey, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return err
	}

	c.certificate = &certAndKey

	return nil
}

func (c *currentCertificate) getCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	c.Lock()
	defer c.Unlock()

	return c.certificate, nil
}
func startHTTPServer(wg *sync.WaitGroup) *http.Server {
	addr := settings.ClientHostname
	if !strings.Contains(addr, ":") {
		addr += ":" + strconv.Itoa(settings.ClientPort)
	}
	srv := &http.Server{Addr: addr}
	srv.IdleTimeout = 5 * time.Minute
	srv.ReadTimeout = 30 * time.Second
	srv.WriteTimeout = 5 * time.Minute
	//cert, err := tls.X509KeyPair([]byte(reply.TLS.Certificate), []byte(reply.TLS.PrivateKey))
	err := cCert.loadCertificate([]byte(reply.TLS.Certificate), []byte(reply.TLS.PrivateKey))
	if err != nil {
		log.Fatalln("failed to create TLS certificate ", err)
	}
	//srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.TLSConfig = &tls.Config{
		GetCertificate:           cCert.getCertificate,
		PreferServerCipherSuites: true,
		MinVersion:               tls.VersionTLS10,
	}
	log.Println("bound to " + addr + " externalPort: " + strconv.Itoa(settings.ClientPort))
	http.HandleFunc("/", handleRequest)

	go func() {
		defer wg.Done() // let main know we are done cleaning up

		// always returns error. ErrServerClosed on graceful close
		if err := srv.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
			// unexpected error. port in use?
			log.Fatalf("ListenAndServe(): %v", err)
		}
	}()

	// returning reference so caller can call Shutdown()
	return srv
}

func readSettingsFile() bool {
	//check if settings file exists
	if st, err := os.Stat(exeDir + "/settings.json"); err == nil {
		settingModTime = st.ModTime()
		// path/to/whatever exists load settings
		jsonFile, err := os.Open(exeDir + "/settings.json")
		if err != nil {
			log.Fatalln(err)
		}
		log.Println("Opened settings file")
		f, err := ioutil.ReadAll(jsonFile)
		if err := json.Unmarshal(f, &settings); err != nil {
			log.Println("Json decoding failed: ", err)
			return false
		}
		//settings.MaxCacheSizeInMebibytes = settings.MaxCacheSizeInMebibytes * 1024 * 1024
		settings.MaxKilobitsPerSecond = settings.MaxKilobitsPerSecond * 1000 / 8
		//TODO: sanity checking  (is the secret the right length, etc...)
		if len(settings.ClientSecret) != 52 {
			log.Println("Client secret need to be a 52 char alphanumeric string")
			return false
		}
		if settings.MaxCacheSizeInMebibytes < 10240 {
			log.Println("You need a cache of over 10GB")
			return false
		}
		return true
	} else if os.IsNotExist(err) {
		// path/to/whatever does *not* exist write default and exit
		log.Println("No settings file found, writing out an example for you to modify")
		file, _ := json.MarshalIndent(settings, "", "	")
		err := ioutil.WriteFile("settings.json", file, sensitiveFilePermission)
		if err != nil {
			log.Println("Could not write settings.json")
		}
		log.Println("successfully read settings file")
		return false
	}
	log.Println("could not tell if settings.json exists")
	return false
}

func sendPing() bool {
	if st, err := os.Stat(exeDir + "/settings.json"); err == nil {
		//check to see if it's updated, if it has then reload settings
		if st.ModTime() != settingModTime {
			log.Println("settings file modified, reloading...")
			if !readSettingsFile() {
				running = false
				return false
			}
		}
	}
	serverData := pingData{
		Secret:       settings.ClientSecret,
		Port:         settings.ClientPort,
		DiskSpace:    settings.MaxCacheSizeInMebibytes * 1024 * 1024,
		NetworkSpeed: settings.MaxKilobitsPerSecond,
		BuildVersion: version,
		TLSCreatedAt: reply.TLS.CreatedAt,
	}
	serverDataMinusSecret := serverData
	serverDataMinusSecret.Secret = "****"
	formData, err := json.Marshal(serverData)
	formDataMinusSecret, _ := json.Marshal(serverDataMinusSecret)
	if err != nil {
		log.Println("Could not serialize json for ping")
		return false
	}
	req, err := http.NewRequest("POST", serverAPIAddress+"ping", bytes.NewBuffer(formData))
	if err != nil {
		log.Println("Error trying to create ping ", err)
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "mdh-go Build."+clientVersion)
	log.Println("sending request", string(formDataMinusSecret))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Println("Error trying to receive ping ", err)
		return false
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	ree := reply

	if err := json.Unmarshal(body, &reply); err != nil {
		log.Println("couldn't decode json for ping: ", err, string(body))
		reply = ree
		return false
	}

	if reply.Compromised == true {
		log.Println("Your client secret is compromised, please update")
		return false
	}
	if len(reply.ImageServer) < 2 {
		log.Println("Failed to get image server information, Something went wrong. Server's reply:\n",
			string(body))
		return false
	}

	s := "false"
	if reply.Compromised {
		s = "true"
	}
	t := "false"
	if reply.Paused {
		t = "true"
	}
	log.Println(textColor("ping received: \n"+"compromised: "+s+" url: "+reply.URL+" image server: "+reply.ImageServer+" latestBuild: "+strconv.Itoa(reply.LatestBuild)+" paused: "+t, 32))
	//log.Println(reply.TokenKey)

	lastPing = time.Now()
	return true
}

func sendStop() bool {
	log.Println("Sending stop")
	resp, err := http.Post(serverAPIAddress+"stop", "application/json", bytes.NewBuffer([]byte(`{"secret":"`+settings.ClientSecret+`"}`)))
	if err != nil {
		log.Fatalln(err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	log.Println("response:\n", string(body))
	return true
}

func main() {

	flag.Parse()
	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			log.Fatal("could not create CPU profile: ", err)
		}
		defer f.Close()
		if err := pprof.StartCPUProfile(f); err != nil {
			log.Fatal("could not start CPU profile: ", err)
		}
		defer pprof.StopCPUProfile()
	}
	flag.Parse()
	if *logFile != "" {
		f, err := os.OpenFile(*logFile,
			os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Println(err)
		}
		defer f.Close()
		mw := io.MultiWriter(os.Stdout, f)
		log.SetOutput(mw)
	}

	exePath, err := os.Executable()
	exeDir = filepath.Dir(exePath)
	running = true
	//opening database
	do := badger.DefaultOptions(exeDir + "/badger")
	//do.Truncate = true
	do.ValueLogLoadingMode = options.FileIO

	db, err = badger.Open(do)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	if !readSettingsFile() {
		running = false
	}
	if len(settings.ServerEndpoint) > 1 {
		serverAPIAddress = settings.ServerEndpoint
	}
	if running {
		//connect to server, send ping
		if sendPing() {
			log.Println("ping succeeded\n",
				"URL is "+reply.URL)
			currentTLSModTime = reply.TLS.CreatedAt
		} else {
			log.Println("ping failed")
			running = false
		}
	}
	if running {
		err := db.View(func(txn *badger.Txn) error {
			item, err := txn.Get([]byte("totalDiskUsed"))
			if err != nil && err.Error() == "Key not found" {
				logNoFatal(err)
				return err
			} else if err != nil {
				running = false
				return err
			}
			err = item.Value(func(val []byte) error {
				in := binary.LittleEndian.Uint64(val)
				log.Println("Disk used is " + strconv.FormatUint(in, 10) + " bytes")
				diskUsed = in
				return nil
			})
			logNoFatal(err)

			return err
		})
		if err != nil {
			log.Println("error disk usage badger: ", err)
		}
		rgx, err = regexp.Compile("^([a-zA-Z]?[0-9]+)-?([a-fA-Z0-9]+)?(.[A-Za-z]+)")
		if err != nil {
			log.Panic(err)
		}
	}
	if running {

		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt)
		//ctx, cancel := context.WithCancel(context.Background())
		go func() {
			oscall := <-c
			log.Printf("system call:%+v", oscall)
			timeOfStop = time.Now()
			//call shutdown
			running = false
			//cancel()
		}()

		log.Println("Starting http server.")
		httpServerExitDone := &sync.WaitGroup{}
		httpServerExitDone.Add(1)
		srv := startHTTPServer(httpServerExitDone)
		log.Println("server started")
		log.Println("test version 2")
		for running {
			time.Sleep(1 * time.Second)
			MaxCacheSizeInBytes := uint64(settings.MaxCacheSizeInMebibytes) * 1024 * 1024
			//log.Println(MaxCacheSizeInBytes, diskUsed, MaxCacheSizeInBytes < diskUsed, int64(MaxCacheSizeInBytes)-int64(diskUsed))
			tbd := time.Now()
			for MaxCacheSizeInBytes < diskUsed {
				evictCache()
				if time.Since(tbd) > 10 {
					log.Println("Broke out of cache evict loop, took > 10 seconds")
					break
				}
			}
			if time.Since(lastPing).Seconds() >= 44 {
				sendPing()
				if !reply.TLS.CreatedAt.Equal(currentTLSModTime) && !reply.TLS.CreatedAt.IsZero() {
					log.Println("Certificate changed, reloading cert")
					cCert.loadCertificate([]byte(reply.TLS.Certificate), []byte(reply.TLS.PrivateKey))
					currentTLSModTime = reply.TLS.CreatedAt
				}
			}
			if serverAPIAddress == "https://mangadex-test.net/" {
				reply.ImageServer = "https://s5.mangadex.org"
			}
		}
		log.Println("stopping server..")
		sendStop()
		log.Println("Stop sent to server, waiting for requests to stop or timeout to expire (max " + strconv.Itoa(settings.GracefulShutdownWaitSeconds) + " seconds)")
		for int(time.Since(timeOfStop).Seconds()) < settings.GracefulShutdownWaitSeconds && int(time.Since(lastRequest).Seconds()) < 15 {
			time.Sleep(1 * time.Second)
			log.Println("waiting to shut down the server")
		}
		log.Println("Shutting down server")
		if err := srv.Shutdown(context.TODO()); err != nil {
			panic(err)
		}
	}
	if *memprofile != "" {
		f, err := os.Create(*memprofile)
		if err != nil {
			log.Fatal("could not create memory profile: ", err)
		}
		defer f.Close()
		runtime.GC() // get up-to-date statistics
		if err := pprof.WriteHeapProfile(f); err != nil {
			log.Fatal("could not write memory profile: ", err)
		}
	}
}
