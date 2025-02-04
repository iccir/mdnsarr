# mdnsarr (mDNS A Record Responder)

mdnsarr is a tiny daemon which listens to mDNS A queries and responds with the appropriate IP address.

## Why?

For web development purposes, I often use `example.local` to reference my local copy of `example.com`.
Typically, I would add these entries to `/etc/hosts`. While this works fine in Safari, it broke in Chrome
several years ago (as Chrome implements its own networking stack).

## Usage

Edit `/etc/mdnsarr` and treat it like `/etc/hosts`:

```
10.0.0.10    ricciadams.local
10.0.0.10    projects.local
10.0.0.10    beacon.local
```   

## Limitations

- No IPv6/AAAA support.
- mdnsarr only sends multicast messages.
- You need to kill the daemon to reload the configuration.
 
## License

Public Domain
