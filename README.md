# hexns

Nameserver for IPv6 which resolves Hexspeak subdomains

## Usage

~~~
make
./hexns 3000 64 1:2:3:4:: kernel.org
dig -p 3000 @127.0.0.1 deadbeef.kernel.org AAAA
~~~

resolves a hexspeek ipv6 address

~~~
; <<>> DiG 9.8.4-rpz2+rl005.12-P1 <<>> -p 3000 @127.0.0.1 deadbeef.kernel.org AAAA
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 20862
;; flags: qr rd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
;; WARNING: recursion requested but not available

;; QUESTION SECTION:
;deadbeef.kernel.org.		IN	AAAA

;; ANSWER SECTION:
deadbeef.kernel.org.	30	IN	AAAA	1:2:3:4::dead:beef

;; Query time: 0 msec
;; SERVER: 127.0.0.1#3000(127.0.0.1)
;; WHEN: Fri Jan 17 13:34:47 2014
;; MSG SIZE  rcvd: 65
~~~

## More ideas

* shans: Translate to sha ip
* colons: Translate color names to ips

## License

~~~
THE BEER-WARE LICENSE:
<mail@daniel-mendler.de> wrote this program. As long as you retain this notice you
can do whatever you want with this stuff. If we meet some day, and you think
this stuff is worth it, you can buy me a beer in return Daniel Mendler
~~~
