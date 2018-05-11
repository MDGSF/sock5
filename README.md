# sock5

implement sock5 protocol.

go run sock5.go

Run this program in your vps, open your local browser, set the proxy to your vps.

Then, you can use google. But data will not be encrypted, this is dangerous.

curl --socks5-hostname localhost:1080 http://www.google.com/

参考 https://github.com/physacco/socks5