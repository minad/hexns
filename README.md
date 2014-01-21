# hexns

Nameserver for IPv6 which resolves Hexspeak subdomains

## Usage

~~~
$ make
$ ./hexns 3000 1:2:3:4:: hexns.org &
$ dig +short -p 3000 @127.0.0.1 deadbeef.hexns.org AAAA
1:2:3:4::dead:beef
$ dig +short -p 3000 @127.0.0.1 leetcode.hexns.org AAAA
1:2:3:4::1337:c0de
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
