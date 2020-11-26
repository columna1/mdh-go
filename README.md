# WARNING This project is unmaintained. This program probably won't work in it's current and I don't have the motivation or time to maintain this project. If you want to take this project over just contact me. otherwise just use the official client or a maintained 3rd party client.

# Mangadex@Home client written in go!
Unofficial client for Mangadex@home written by columna1 with help from [jeremiejig](https://github.com/jeremiejig)
## Support
This client was written mostly as an educational exercise as well as for fun. I will provide little to no official support. Though feel free to file issues if you run across them. However, if you see me around I'll answer questions.  
  
**File structure for this client and the official client are NOT compatible. DO NOT attempt to use your cache from the official client, this will just waste disk space!**  
  
While this client has been used in production, on the official production servers. I cannot guarantee that it works correctly and is bug free.  
**USE AT YOUR OWN RISK**  
## Configuration
While this client uses a configuration similar to the official client, it is not the same. Because of this you should take care if transferring settings from the official client to this one.

Example Config:

```json
    {
	"ClientSecret": "ClientSecretHere",
	"ClientHostname": "0.0.0.0",
	"ClientPort": 443,
	"GracefulShutdownWaitSeconds": 120,
	"MaxCacheSizeInMebibytes": 204080,
	"MaxKilobitsPerSecond": 0,
	"MaxMebibytesPerHour": 0,
	"ServerEndpoint": ""
}
```
Upon launching without a config the client will write out a blank settings file for you to fill out.

Here is a rough explanation of the config values:

### `ClientSecret`
You get this from your clients page on mangadex.org this should be 52 chars long
### `ClientHostname`
Set a hostname for people to connect with, leave this blank or 0.0.0.0 if you don't know what this is for
### `ClientPort`
This is the port readers will connect to you with. If possible it is preferred to use port 443. However port 443 is a privileged port and if you don't have administrator or root access you may not be able to use it. In that case the de-facto standard port is 44300.
### `GracefulShutdownWaitSeconds`
This is the maximum number of seconds that the client will wait after receiving a shutdown signal. This allows readers who are still grabbing images to continue without interruption. The server may shut down earlier if no requests are received within a 10 second period.
### `MaxCacheSizeInMebibytes`
This is roughly how much disk space the client will use before it starts deleting old entries. This is only a measure of file size and not disk size therefore don't allocate all your disk space or you may run into unintended behavior.
### `MaxKilobitsPerSecond`
This isn't used in the client. This is just sent to the central server to help determine how much traffic to send. Set to 0 for "unlimited".
### `MaxMebibytesPerHour`
This is not used internally, just sent to the main server.
### `ServerEndpoint`
Used to change the main server endpoint. This is used for debugging purposes, leave it blank.

## Architecture
This client uses [badger](https://github.com/dgraph-io/badger) to store metadata about each file. The metadata stored includes the chapter hash + filename, content-type string sent to the reader, file size, and time last accessed.  
The total disk space used is also stored in a db entry. Disk space used is never directly measured from disk.  
  
When the client receives a request it looks it up in the cache folder. The cache folder is structured like so:  
We use the chapter hash provided in the request to store all files in a chapter in a single directory. For Example the image   
`/data/8172a46adc798f4f4ace6663322a383e/B18.png`  
is stored with a path like so:
`cache/data/81/72/a4/8172a46adc798f4f4ace6663322a383e/B18.png`  
  
Old data is evicted based on an LRU approximation. This isn't perfect but should work well enough. This decision was made to reduce file space used and make cache eviction faster and less resource intensive.
  
**This client stores images by chapter ID in an un-encrypted fashion. If this is a concern for you Don't use this client!**

## Thanks to contributors!
If you have a feature you want implemented or have an idea to make this client better please feel free to submit a PR.  
Special thanks to the following:  
[jeremiejig](https://github.com/jeremiejig) for helping solve bugs, providing style and other general improvements! Thanks a bunch!
