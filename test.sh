#!/bin/bash

stop() {
    if [[ "$pid" != "" ]]; then
      kill $pid
      wait $pid 2>/dev/null
    fi
    killall -q hexns
}

start() {
    stop
    domain=$3
    ./hexns 3000 $1 $2 $3 2>/dev/null >/dev/null &
    pid=$!
}

status=0
lookup() {
    output=$(dig -p 3000 @127.0.0.1 $1.$domain AAAA)
    #echo "$output" | grep 'WARNING'
    #echo "$output" | grep 'warning'
    if echo "$output" | grep -Po "30\\s+IN\\s+AAAA\\s+$2\$" > /dev/null; then
	echo -n '.'
    else
	echo -e "\nERROR $1.$domain"
	status=1
    fi
}

start 64 1:2:3:4:: kernel.org
lookup dadadadadadadada 1:2:3:4:dada:dada:dada:dada
lookup dadadadadadadadaabcd 1:2:3:4:dada:dada:dada:dada
lookup dadadadadadadadaab 1:2:3:4:dada:dada:dada:dada
lookup coffee 1:2:3:4::c0:ffee
lookup cä 1:2:3:4::cae
lookup cö 1:2:3:4::c0e
lookup cäf 1:2:3:4::caef
lookup cöf 1:2:3:4::c0ef
stop

echo
exit $status