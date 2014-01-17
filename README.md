# hexns

Nameserver for IPv6 which resolves Hexspeak subdomains

## Usage

~~~
make
./hexns 3000 1:2:3:4::
dig -p 3000 @127.0.0.1 deadbeaf.kernel.org AAAA
~~~

resolves a hexspeek ipv6 address

~~~
; <<>> DiG 9.9.2-P2 <<>> -p 3000 @127.0.0.1 deadbeaf.kernel.org AAAA
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 64211
;; flags: qr rd ad; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
;; WARNING: recursion requested but not available

;; QUESTION SECTION:
;deadbeaf.kernel.org.		IN	AAAA

;; ANSWER SECTION:
deadbeaf.kernel.org.	30	IN	AAAA	1:2:3:4:dead:beaf:feff:e10f

;; Query time: 1 msec
;; SERVER: 127.0.0.1#3000(127.0.0.1)
;; WHEN: Fri Jan 17 04:58:05 2014
;; MSG SIZE  rcvd: 65
~~~

## License

~~~
THE BEER-WARE LICENSE:
<mail@daniel-mendler.de> wrote this program. As long as you retain this notice you
can do whatever you want with this stuff. If we meet some day, and you think
this stuff is worth it, you can buy me a beer in return Daniel Mendler
~~~
