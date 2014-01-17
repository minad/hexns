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
    ./hexns 3000 $1 $2 $3 > /dev/null &
    pid=$!
}

status=0
aaaa() {
    output=$(dig -p 3000 @127.0.0.1 $1.$domain AAAA $1.$domain A)
    #echo "$output" | grep -i 'WARNING'
    if echo "$output" | grep -P "30\\s+IN\\s+AAAA\\s+$2\$" > /dev/null; then
	echo -n '.'
    else
	echo -e "\nERROR $1.$domain"
	#echo "$output" | grep -P AAAA
	status=1
    fi

    output=$(dig -p 3000 @127.0.0.1 $1.$domain ANY)
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
	else
	    echo -n '.'
	fi
    done
}

start 64 1:2:3:4:: kernel.org
aaaa dadadadadadadada 1:2:3:4:dada:dada:dada:dada
aaaa dada.dada.dada.dada 1:2:3:4:dada:dada:dada:dada
aaaa dadadadadadadadaabcd 1:2:3:4:dada:dada:dada:dada
aaaa dadad.ad.ada.dad.adaabcd 1:2:3:4:dada:dada:dada:dada
aaaa dadadadadadadadaab 1:2:3:4:dada:dada:dada:dada
aaaa coffee 1:2:3:4::c0:ffee
aaaa c.offee 1:2:3:4::c0:ffee
aaaa cä 1:2:3:4::cae
aaaa c.ä 1:2:3:4::cae
aaaa zö 1:2:3:4::c0e
aaaa z.ö 1:2:3:4::c0e
aaaa zäf 1:2:3:4::caef
aaaa zä.f 1:2:3:4::caef
aaaa zöf 1:2:3:4::c0ef
aaaa zöööf 1:2:3:4::c0e0:e0ef
aaaa z.öf 1:2:3:4::c0ef

start 32 a:b:: org
aaaa dadadadadadadada a:b::dada:dada:dada:dada
aaaa coffee a:b::c0:ffee
aaaa cä a:b::cae
aaaa zö a:b::c0e
aaaa zäf a:b::caef
aaaa zöf a:b::c0ef
aaaa zöööf a:b::c0e0:e0ef
stop

echo
exit $status
