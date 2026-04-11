# v8CTF Submission Reproduction

The setup we use to reproduce v8CTF submissions consists of two kCTF challenges:
* repro-chrome
* repro-exploit

tl;dr: the chrome container will run chrome headless that proxies all requests through the exploit container.

## Chrome

`repro-chrome` hosts a setup similar to the `chrome` challenge.
We run chrome in headless mode without a sandbox and there's a flag on the filesystem.
The main difference is in how we start chrome (see `challenge/chal`):
* The url to open always points to a fixed domain ('https://evil.com/exp.html')
* We disable TLS validation with `--ignore-certificate-errors`
* And it proxies all requests through `repro-exploit` using the `--proxy-server` flag.

## Exploit

`repro-exploit` hosts the exploit that needs to be added in `challenge/exploit.tar.gz`.

By default, it runs `mitmdump` (from [mitmproxy](https://mitmproxy.org/)) and a webserver.
The webserver runs on port 1234 and serves the contents of the provided `exploit.tar.gz`.
`mitmdump` listens on port 1337 and proxies all requests to the webserver.

Participants can provide their own script if they add a `doit.sh` in the exploit archive.

*Note*: the webserver needs to provide a `/exp.html` since that will be the URL that will get loaded initially.

## Local Reproduction

To reproduce an exploit locally, you can check out the [kCTF documentation](https://google.github.io/kctf/).

You need to:
* add an archive containing `exp.html` at `repro-exploit/challenge/exploit.tar.gz`
* start both `repro-chrome` and `repro-exploit`
* add a port-forward for the `repro-chrome` challenge (see [local-testing.html](https://google.github.io/kctf/local-testing.html))
* and connect to the local port with netcat.

If the exploit works, it should print the flag.
