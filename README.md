# Simple Proxy Server

## Task Requirements

Implement a simple proxy server using the SOCKS5 protocol. You only need to support the `CMD CONNECT` (to establish a TCP connection). Authentication is not required (for `AUTH`, only supporting method `0` is necessary).

## Local Testing

It is recommended to use a browser extension like Proxy SwitchyOmega to set the proxy to your server. After setting it up, try to access the internet and observe the traffic on your proxy server.

You can print the addresses being routed through your program during runtime to help with debugging.

Alternatively, you can use the `all_proxy` environment variable to debug from the command line:

```sh
all_proxy=socks5h://localhost:8080 curl example.com
```

The evaluation script will be released later this week.

## Deadline

Tentatively due before Monday of the second week.

## Reference Material

[RFC 1928: SOCKS Protocol Version 5](https://www.rfc-editor.org/rfc/rfc1928)
