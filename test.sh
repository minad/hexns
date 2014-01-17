#!/bin/bash

stop() {
    if [[ "$pid" != "" ]]; then
	kill $pid
	wait $pid 2>/dev/null
    fi
    killall -q hexns
    pid=''
}

start() {
    stop
    domain=$3
    ./hexns 3000 $1 $2 $3 2>>test.log >>test.log &
    pid=$!
}

status=0
aaaa() {
    output=$(dig -p 3000 @127.0.0.1 $1.$domain AAAA)
    #echo "$output" | grep -i 'WARNING'
    if echo "$output" | grep -P "30\\s+IN\\s+AAAA\\s+$2\$" > /dev/null; then
	echo -n '.'
    else
	echo -e "\nERROR $1.$domain"
	status=1
    fi

    for record in TXT MX A CNAME; do
	output=$(dig -p 3000 @127.0.0.1 $1.$domain $record)
        #echo "$output" | grep -i 'WARNING'
	if echo "$output" | grep -P "ANSWER SECTION" > /dev/null; then
	    echo -e "\nERROR Record $record found"
	fi
    done
}

start 64 1:2:3:4:: kernel.org
aaaa dadadadadadadada 1:2:3:4:dada:dada:dada:dada
aaaa dadadadadadadadaabcd 1:2:3:4:dada:dada:dada:dada
aaaa dadadadadadadadaab 1:2:3:4:dada:dada:dada:dada
aaaa coffee 1:2:3:4::c0:ffee
aaaa cä 1:2:3:4::cae
aaaa cö 1:2:3:4::c0e
aaaa cäf 1:2:3:4::caef
aaaa cöf 1:2:3:4::c0ef

start 32 a:b:: org
aaaa dadadadadadadada a:b::dada:dada:dada:dada
aaaa coffee a:b::c0:ffee
aaaa cä a:b::cae
aaaa cö a:b::c0e
aaaa cäf a:b::caef
aaaa cöf a:b::c0ef
stop

echo
exit $status