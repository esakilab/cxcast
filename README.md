#### memo

To join multicast address group, use `socat`.

- `socat STDIO UDP4-RECV:1234,ip-add-membership=239.0.0.1:eth0`
