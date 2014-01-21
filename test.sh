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
    port=$1
    ttl=$2
    addr=$3
    domain=$4
    domain2=$5
    ./hexns -n nameserver1 -n slavenameserver -vp $1 -t $2 $3 $4 $5 >> test.log &
    pid=$!

    output=$(dig -p $port @127.0.0.1 $domain AAAA)
    #echo "$output"
    echo "$output" | grep -i 'WARNING'
    if echo "$output" | grep -P "$ttl\\s+IN\\s+AAAA\\s+${addr%/*}\$" > /dev/null; then
	echo -n '.'
    else
	echo -e "\nERROR $domain"
	#echo "$output" | grep -P AAAA
	status=1
    fi
}

status=0
aaaa() {
    output=$(dig -p $port @127.0.0.1 $1.$domain AAAA $1.$domain A)
    echo "$output" | grep -i 'WARNING'
    if echo "$output" | grep -P "$ttl\\s+IN\\s+AAAA\\s+$2\$" > /dev/null; then
	echo -n '.'
    else
	echo -e "\nERROR $1.$domain"
	#echo "$output" | grep -P AAAA
	status=1
    fi
    if echo "$output" | grep -P "$domain\\.\\s+$ttl\\s+IN\\s+NS\\s+nameserver1\\.$domain\\.\$" > /dev/null; then
	echo -n '.'
    else
	echo -e "\nERROR $1.$domain"
	#echo "$output" | grep -P AAAA
	status=1
    fi
    if echo "$output" | grep -P "$domain\\.\\s+$ttl\\s+IN\\s+NS\\s+slavenameserver\\.$domain\\.\$" > /dev/null; then
	echo -n '.'
    else
	echo -e "\nERROR $1.$domain"
	#echo "$output" | grep -P AAAA
	status=1
    fi
    if echo "$output" | grep -P "nameserver1\\.$domain\\.\\s+$ttl\\s+IN\\s+AAAA" > /dev/null; then
	echo -n '.'
    else
	echo -e "\nERROR $1.$domain"
	#echo "$output" | grep -P AAAA
	status=1
    fi
    if echo "$output" | grep -P "slavenameserver\\.$domain\\.\\s+$ttl\\s+IN\\s+AAAA" > /dev/null; then
	echo -n '.'
    else
	echo -e "\nERROR $1.$domain"
	#echo "$output" | grep -P AAAA
	status=1
    fi

    output=$(dig -p $port @127.0.0.1 $1.$domain2 AAAA $1.$domain2 A)
    echo "$output" | grep -i 'WARNING'
    if echo "$output" | grep -P "$ttl\\s+IN\\s+AAAA\\s+$2\$" > /dev/null; then
	echo -n '.'
    else
	echo -e "\nERROR $1.$domain2"
	echo "$output" | grep -P AAAA
	status=1
    fi

    output=$(dig -p $port @127.0.0.1 $1.$domain ANY)
    echo "$output" | grep -i 'WARNING'
    if echo "$output" | grep -P "$ttl\\s+IN\\s+AAAA\\s+$2\$" > /dev/null; then
	echo -n '.'
    else
	echo -e "\nERROR $1.$domain"
	status=1
    fi

    for record in TXT MX A CNAME NS; do
	output=$(dig -p $port @127.0.0.1 $1.$domain $record)
        echo "$output" | grep -i 'WARNING'
	if echo "$output" | grep -P "ANSWER SECTION" > /dev/null; then
	    echo -e "\nERROR Record $record found"
	else
	    echo -n '.'
	fi
    done

    output=$(nslookup -port=$port -type=any $1.$domain 127.0.0.1)
    echo "$output" | grep -i 'Non-authoritative'
    if echo "$output" | grep -P "has\\s+AAAA\\s+address\\s+$2\$" > /dev/null; then
	echo -n '.'
    else
	echo -e "\nERROR $1.$domain"
	#echo "$output" | grep -P AAAA
	status=1
    fi
}

rm -f test.log
start 3000 10 1:2:3:4::180 kernel.org laber.org
aaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 1:2:3:4:aaaa:aaaa:aaaa:aaaa
aaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc.dddddddddddddddddddddddddddddddddddddddddddddddddd 1:2:3:4:aaaa:aaaa:aaaa:aaaa
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
aaaa zöph 1:2:3:4::c0ef
aaaa ZÖPH 1:2:3:4::c0ef
aaaa zofenpeter 1:2:3:4:0:c:feb:e7e7
aaaa ozfenbe7erdadadadada 1:2:3:4:cfe:be7e:7dad:adad
aaaa be7eozferdadadadada 1:2:3:4:be7e:cfe:7dad:adad
aaaa leet 1:2:3:4::1337
aaaa daleetda 1:2:3:4::da13:37da
aaaa coooooa 1:2:3:4::c00:a

start 3001 500 a:b:: org du
aaaa dadadadadadadada a:b::dada:dada:dada:dada
aaaa coffee a:b::c0:ffee
aaaa cä a:b::cae
aaaa zö a:b::c0e
aaaa zäf a:b::caef
aaaa zöf a:b::c0ef
aaaa ZÖF a:b::c0ef
aaaa ZÄF a:b::caef
aaaa zöööf a:b::c0e0:e0ef
aaaa zöph a:b::c0ef
aaaa zofenpeter a:b::c:feb:e7e7

start 3001 500 a:b::/96 org x
aaaa dadadadadadadada a:b::dada:dada

start 3001 500 a:b::/94 org y
aaaa dadadadadadadada a:b::dada:dada

output=$(dig -p $port @127.0.0.1 abc AAAA)
echo "$output" | grep -i 'WARNING'
if echo "$output" | grep -P "ANSWER SECTION" > /dev/null; then
    echo -e "\nERROR Record AAAA found"
else
    echo -n '.'
fi

output=$(dig -p $port @127.0.0.1 test$domain AAAA)
echo "$output" | grep -i 'WARNING'
if echo "$output" | grep -P "ANSWER SECTION" > /dev/null; then
    echo -e "\nERROR Record AAAA found"
else
    echo -n '.'
fi

stop

echo
exit $status
