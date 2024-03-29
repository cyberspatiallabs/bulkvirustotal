# Bulk VirusTotal Tool

**A command line utility for looking up a batch of domains contained in a file using the VirusTotal API V3**

**Lovingly written in Go** ❤️

The user must provide the file path and a VirusTotal API Key.

You can get a VirusTotal API key by signing up for a [free VirusTotal account](https://www.virustotal.com/gui/join-us).

The code is setup to sleep between indiviudal lookups to not exceed the VT free tier rate limit.

Reference:  [VirusTotal API V3 Domain Info](https://docs.virustotal.com/reference/domain-info)

## Building

  1. [Install go 1.22 or higher](https://go.dev/doc/install).   

  2. Then build:

  ```
  go build
  ```

## Releases

Don't want to compile yourself?  You can grab one of the precompiled github releases [here](https://github.com/cyberspatiallabs/bulkvirustotal/releases).

Note:  Some virus scanners might flag the release binary as a Trojan or other malicious code.  This may be due to the string "virus" or the API use.
If you don't want to trust the release, install go and build it yourself, its very easy and satisfying to build your own stuff.

## Usage

```
./bulkvt -file urls -apikey 682764874768467836842
```

Where urls is a file like the following:

```
p.parrable.com
img.3lift.com
amp.dev
play.google.com
dpm.demdex.net
us-central1-amp-error-reporting.cloudfunctions.net
acdn.adnxs-simple.com
cdn.botframework.com
wns2-bn3p.notify.windows.com
gem.gbc.criteo.com
console.appnexus.com
.
.
.
```

This will yield the following:


```
 _____     __    __   __       __  ___ ____    ____ .___________.
|   _  \  |  |  |  | |  |     |  |/  / \   \  /   / |           |
|  |_|  | |  |  |  | |  |     |  '  /   \   \/   /   ---|  |----
|   _  <  |  |  |  | |  |     |    <     \      /       |  |     
|  |_| |  |  ----  | |  ----. |  .  \     \    /        |  |     
|______/   \______/  |_______||__|\__\     \__/         |__|     

Performing lookup for domain: p.parrable.com
{
    "data": {
        "id": "u-42c8eae2148249bb1791a7000f4d04ea9d5e56bbdc209c422a54e04144e11a52-1709342764",
        "type": "analysis",
        "links": {
            "self": "https://www.virustotal.com/api/v3/analyses/u-42c8eae2148249bb1791a7000f4d04ea9d5e56bbdc209c422a54e04144e11a52-1709342764",
            "item": "https://www.virustotal.com/api/v3/urls/42c8eae2148249bb1791a7000f4d04ea9d5e56bbdc209c422a54e04144e11a52"
        },
        "attributes": {
            "results": {},
            "stats": {
                "malicious": 0,
                "suspicious": 0,
                "undetected": 0,
                "harmless": 0,
                "timeout": 0
            },
            "date": 1709342764,
            "status": "queued"
        }
    },
    "meta": {
        "url_info": {
            "id": "42c8eae2148249bb1791a7000f4d04ea9d5e56bbdc209c422a54e04144e11a52",
            "url": "http://p.parrable.com/"
        }
    }
}
(sleeping to not exceed API throttle)
```
