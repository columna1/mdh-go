package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"io/ioutil"
	"log"
	"math"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	badger "github.com/dgraph-io/badger/v2"
	"github.com/dgraph-io/badger/v2/pb"
)

type configuration struct {
	ClientSecret                string
	ClientHostname              string
	ClientPort                  int
	GracefulShutdownWaitSeconds int
	MaxCacheSizeInMebibytes     int
	MaxKilobitsPerSecond        int
	MaxMebibytesPerHour         int
}
type pingData struct {
	Secret       string `json:"secret"`
	Port         int    `json:"port"`
	DiskSpace    int    `json:"disk_space"`
	NetworkSpeed int    `json:"network_speed"`
	BuildVersion int    `json:"build_version"`
}
type serverReply struct {
	ImageServer string `json:"image_server"`
	URL         string `json:"url"`
	Compromised bool   `json:"compromised"`
	LatestBuild int    `json:"latest_build"`
	TLS         struct {
		CreatedAt   string `json:"created_at"`
		PrivateKey  string `json:"private_key"`
		Certificate string `json:"certificate"`
	} `json:"tls"`
}
type keyValue struct {
	ContentType  string `json:"Content_Type"`
	LastAccessed int64  `json:"last_accessed"`
	FileSize     int64  `json:"file_size"`
	LastModified string `json:"last_modified"`
}

//file structure will be
//cache/data/ff/ff/ff/ffffffaaaaaa/file.1
//cache/data-saver/ff/ff/ff/ffffffaaaaaaaa/file.2

var settings configuration
var reply serverReply
var version = 13
var exeDir string

var cacheDir = "cache/"
var serverAPIAddress = "https://mangadex-test.net/"

var db *badger.DB
var running bool
var diskUsed uint64
var lastRequest time.Time
var timeOfStop time.Time

func getFilePath(words []string) string {
	return exeDir + "/" + cacheDir + words[0] + "/" + words[1][0:2] + "/" + words[1][2:4] + "/" + words[1][4:6] + "/" + words[1] + "/" + words[2]
}
func getFileDir(words []string) string {
	return exeDir + "/" + cacheDir + words[0] + "/" + words[1][0:2] + "/" + words[1][2:4] + "/" + words[1][4:6] + "/" + words[1]
}
func getFilePathFromBytes(id []byte) string {
	is := string(id)
	words := strings.Split(is, "/")
	return exeDir + "/" + cacheDir + words[0] + "/" + words[1][0:2] + "/" + words[1][2:4] + "/" + words[1][4:6] + "/" + words[1] + "/" + words[2]
}

func checkForFile(words []string) (exists bool) {
	//urls will look like /data/aaf33f3f33f3ff35abaf/m2.png
	//words := strings.Split(file, "/")
	filePath := getFilePath(words)
	//log.Println(filePath)
	if _, err := os.Stat(filePath); err == nil {
		//log.Println("exists")
		exists = true
	} else if os.IsNotExist(err) {
		//log.Println("does not exist")
		exists = false
	}
	return
}

func handle(err error) {
	if err != nil {
		log.Fatalln(err)
	}
}
func handleNoFatal(err error) {
	if err != nil {
		log.Println(err)
	}
}

func evictCache() { //just blindly removes something from cache
	// The following code generates 10 random keys
	lowestNum := int64(math.MaxInt64)
	var lowestKey []byte
	var lowestNumSize int64
	for i := 0; i < 10; i++ {
		var keys [][]byte
		count := 0
		stream := db.NewStream()
		stream.NumGo = 16

		// overide stream.KeyToList as we only want keys. Also
		// we can take only first version for the key.
		stream.KeyToList = func(key []byte, itr *badger.Iterator) (*pb.KVList, error) {
			l := &pb.KVList{}
			// Since stream framework copies the item's key while calling
			// KeyToList, we can directly append key to list.
			l.Kv = append(l.Kv, &pb.KV{Key: key})
			return l, nil
		}

		// The bigger the sample size, the more randomness in the outcome.
		sampleSize := 1000
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		stream.Send = func(l *pb.KVList) error {
			if count >= sampleSize {
				return nil
			}
			// Collect "keys" equal to sample size
			for _, kv := range l.Kv {
				keys = append(keys, kv.Key)
				count++
				if count >= sampleSize {
					cancel()
					return nil
				}
			}
			return nil
		}

		if err := stream.Orchestrate(ctx); err != nil && err != context.Canceled {
			panic(err)
		}
		// Pick a random key from the list of keys
		//fmt.Printf("%s\n", keys[rand.Intn(len(keys))])

		err := db.View(func(txn *badger.Txn) error {
			item, err := txn.Get(keys[rand.Intn(len(keys))])
			err = item.Value(func(val []byte) error {
				var entry keyValue
				json.Unmarshal(val, &entry)
				if entry.LastAccessed < lowestNum {
					lowestKey = keys[rand.Intn(len(keys))]
					lowestNum = entry.LastAccessed
					lowestNumSize = entry.FileSize
				}
				return nil
			})
			handleNoFatal(err)

			return err
		})
		if err != nil {
			log.Println("err")
			log.Println(err)
		}
	}
	//delete lowest key and update diskuse
	err := db.Update(func(txn *badger.Txn) error {
		//delete key
		log.Println("deleted " + string(lowestKey))
		log.Println("removing " + getFilePathFromBytes(lowestKey))
		os.Remove(getFilePathFromBytes(lowestKey))
		err := txn.Delete(lowestKey)
		return err
	})
	if err != nil {
		log.Println("err")
		log.Println(err)
	} else {
		updateTotalDiskUse(0 - int(lowestNumSize))
	}
}

func updateTotalDiskUse(bytes int) {
	log.Println("updating Disk use")
	log.Println(bytes)
	err := db.Update(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte("totalDiskUsed"))
		if err != nil && err.Error() == "Key not found" {
			log.Println("Disk usage stat not found, creating it. Using " + strconv.Itoa(bytes) + " bytes")
			v := make([]byte, 8)
			binary.LittleEndian.PutUint64(v, uint64(bytes))
			diskUsed = uint64(bytes)
			err := txn.Set([]byte("totalDiskUsed"), v)
			handleNoFatal(err)
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
			log.Println("Disk used is now " + strconv.FormatUint(in, 10) + " bytes")
			diskUsed = in
			v := make([]byte, 8)
			binary.LittleEndian.PutUint64(v, in)
			err := txn.Set([]byte("totalDiskUsed"), v)
			handleNoFatal(err)
			return nil
		})
		handleNoFatal(err)

		return err
	})
	if err != nil {
		log.Println("err")
		log.Println(err)
	}
}

func handleCacheHit(w http.ResponseWriter, r *http.Request, words []string) {
	//cache hit
	//TODO: insert key if it's missing
	//TODO: browser cache
	st := time.Now()
	contentType := ""
	lm := ""
	id := words[0] + "/" + words[1] + "/" + words[2]
	log.Println("Cache hit for " + id)
	err := db.Update(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(id))
		handleNoFatal(err)
		if err != nil {
			return err
		}
		err = item.Value(func(val []byte) error {
			// This func with val would only be called if item.Value encounters no error.

			// Accessing val here is valid.
			//fmt.Printf("The answer is: %s\n", val)
			var entry keyValue
			json.Unmarshal(val, &entry)
			contentType = entry.ContentType
			lm = entry.LastModified
			v, _ := json.Marshal(entry)
			txn.Set([]byte(id), v)
			entry.LastAccessed = time.Now().Unix()

			json, _ := json.Marshal(entry)
			err := txn.Set([]byte(id), json)
			handleNoFatal(err)
			return nil
		})
		handleNoFatal(err)

		return err
	})
	if err != nil {
		log.Println("err")
		log.Println(err)
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

	http.ServeFile(w, r, getFilePath(words))
	log.Print("Done serving " + id + " in " + strconv.Itoa(int(time.Since(st).Milliseconds())) + "ms")
}

func handleCacheMiss(w http.ResponseWriter, r *http.Request, words []string) {
	st := time.Now()
	id := words[0] + "/" + words[1] + "/" + words[2]
	log.Println("Cache miss for " + id)
	resp, err := http.Get(reply.ImageServer + "/" + words[0] + "/" + words[1] + "/" + words[2])
	if err != nil {
		//fail and send a 404 response back to the client
		log.Println("failed to get image from upstream")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	ct := resp.Header.Get("Content-Type")
	lmt := resp.Header.Get("Last-Modified")
	log.Println(lmt)
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

	//imgData, _ := ioutil.ReadAll(resp.Body) //NewReader(resp.Body)
	dir := getFileDir(words)
	os.MkdirAll(dir, 0664)
	fn := getFilePath(words)
	f, fileerr := os.Create(fn)
	if fileerr != nil {
		log.Println("could not open file to write")
	}
	//ioutil.WriteFile(fn, imgData, 0664)
	buf := make([]byte, 1000000) //one megabyte
	tb := 0
	for {
		n, err := resp.Body.Read(buf)
		w.Write(buf[:n])
		if fileerr == nil {
			f.Write(buf[:n])
		}
		tb += n
		//log.Println(n, err)
		if err == io.EOF {
			break
		}
	}
	f.Close()

	log.Println("Got file from upstream in " + strconv.Itoa(int(time.Since(st).Milliseconds())) + "ms")

	//w.Write(imgData)
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
		log.Println(err)
	}
	log.Println("Done serving " + id + " in " + strconv.Itoa(int(time.Since(st).Milliseconds())) + "ms")
	updateTotalDiskUse(tb)
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	lastRequest = time.Now()
	words := strings.Split(r.URL.String(), "/")
	//log.Println(words)
	indOffset := 0
	for i := 0; i < len(words); i++ {
		if words[i] == "data" || words[i] == "data-saver" {
			indOffset = i
			break
		}
	}
	if (words[indOffset] == "data" || words[indOffset] == "data-saver") && len(words) > indOffset+2 {
		if checkForFile(words[indOffset : indOffset+3]) {
			handleCacheHit(w, r, words[indOffset:indOffset+3])
		} else {
			//cache miss
			//get file and serve it to disk and to reader
			handleCacheMiss(w, r, words[indOffset:indOffset+3])
		}
	} else if r.URL.String() == "/stop" {
		running = false
		w.Write([]byte("Shutting server down!"))
		timeOfStop = time.Now()
	} else {
		//error
		log.Printf("failed to serve request " + r.URL.String())
	}
	//fmt.Println(r.URL)
}

func startHTTPServer(wg *sync.WaitGroup) *http.Server {
	srv := &http.Server{Addr: settings.ClientHostname + ":" + strconv.Itoa(settings.ClientPort)}
	log.Println(settings.ClientHostname + ":" + strconv.Itoa(settings.ClientPort))
	http.HandleFunc("/", handleRequest)

	go func() {
		defer wg.Done() // let main know we are done cleaning up

		// always returns error. ErrServerClosed on graceful close
		if err := srv.ListenAndServeTLS(exeDir+"/cert.crt", exeDir+"/cert.key"); err != http.ErrServerClosed {
			// unexpected error. port in use?
			log.Fatalf("ListenAndServe(): %v", err)
		}
	}()

	// returning reference so caller can call Shutdown()
	return srv
}

func readSettingsFile() bool {
	//check if settings file exists
	if _, err := os.Stat(exeDir + "/settings.json"); err == nil {
		// path/to/whatever exists load settings
		jsonFile, err := os.Open(exeDir + "/settings.json")
		if err != nil {
			log.Fatalln(err)
		}
		log.Println("Opened settings file")
		f, err := ioutil.ReadAll(jsonFile)
		if err := json.Unmarshal(f, &settings); err != nil {
			log.Println("Json decoding failed")
			log.Println(err)
			return false
		}
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
		err := ioutil.WriteFile("settings.json", file, 0644)
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
	serverData := pingData{
		Secret:       settings.ClientSecret,
		Port:         settings.ClientPort,
		DiskSpace:    settings.MaxCacheSizeInMebibytes,
		NetworkSpeed: settings.MaxKilobitsPerSecond,
		BuildVersion: version,
	}
	formData, err := json.Marshal(serverData)
	if err != nil {
		log.Fatalln("Could not serialize json for ping")
		return false
	}
	req, err := http.NewRequest("POST", serverAPIAddress+"ping", bytes.NewBuffer(formData))
	if err != nil {
		log.Fatalln(err)
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "MangaDex@Home Build.1.1.0")
	log.Println("sending request", string(formData))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatalln(err)
		return false
	}
	body, err := ioutil.ReadAll(resp.Body)
	//log.Println("response:")
	//log.Println(string(body))

	if err := json.Unmarshal(body, &reply); err != nil {
		log.Fatalln(err)
		return false
	}

	if reply.Compromised == true {
		log.Println("Your client secret is compromised, please update")
		return false
	}
	if len(reply.ImageServer) < 2 {
		log.Println("Failed to get image server information, Something went wrong. Server's reply:")
		log.Println(string(body))
		return false
	}

	tls := reply.TLS
	ioutil.WriteFile(exeDir+"/cert.key", []byte(tls.PrivateKey), 0664)
	ioutil.WriteFile(exeDir+"/cert.crt", []byte(tls.Certificate), 0664)
	return true
}

func sendStop() bool {
	log.Println("Sending stop")
	resp, err := http.Post(serverAPIAddress+"stop", "application/json", bytes.NewBuffer([]byte(`{"secret":"h8gb7v8wgvxhgmvcsbc31nvmxk2f69mjcww2yw9xs8ha4d1f26q0"}`)))
	if err != nil {
		log.Fatalln(err)
	}

	body, err := ioutil.ReadAll(resp.Body)
	log.Println("response:")
	log.Println(string(body))
	return true
}

func main() {
	exePath, err := os.Executable()
	exeDir = filepath.Dir(exePath)
	running = true
	//opening database
	do := badger.DefaultOptions(exeDir + "/badger")
	do.Truncate = true
	db, err = badger.Open(do)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	//evictCache()

	/*
		err = db.Update(func(txn *badger.Txn) error {
			t := keyValue{
				ContentType:  "image/png",
				LastAccessed: 1593077955,
			}
			json, _ := json.Marshal(t)
			err := txn.Set([]byte("data/8172a46adc798f4f4ace6663322a383e/B18.png"), json)
			return err
		})
		if err != nil {
			log.Fatalln(err)
		}*/

	if !readSettingsFile() {
		running = false
	}
	if running {
		//connect to server, send ping
		sendPing()
		log.Println("ping succeeded")
		log.Println("URL is " + reply.URL)
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

		log.Println("Starting html server (not really(yet))")
		httpServerExitDone := &sync.WaitGroup{}
		httpServerExitDone.Add(1)
		srv := startHTTPServer(httpServerExitDone)
		log.Println("server started")
		//<-ctx.Done()
		/*go func() {
			log.Println("shutting down in 30 seconds")
			time.Sleep(29 * time.Second)
			running = false
		}()*/
		for running {
			//log.Println("heartbeat")
			time.Sleep(1 * time.Second)
			for uint64(settings.MaxCacheSizeInMebibytes)*1024 < diskUsed {
				evictCache()
			}
		}
		log.Println("stopping server..")
		sendStop()
		log.Println("Stop sent to server, waiting for requests to stop or timeout to expire (max " + strconv.Itoa(settings.GracefulShutdownWaitSeconds) + " seconds_")
		for int(time.Since(timeOfStop)/time.Second) < settings.GracefulShutdownWaitSeconds && int(time.Since(lastRequest)/time.Second) < 10 {
			time.Sleep(1 * time.Second)
			log.Println("waiting to shut down the server")
		}
		log.Println("Shutting down server")
		if err := srv.Shutdown(context.TODO()); err != nil {
			panic(err)
		}
	}
}
