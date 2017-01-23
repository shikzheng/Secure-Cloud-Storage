#/usr/bin/bash

if [ $# -eq 0 ]; then
    echo "usage: $0 <name>"
    exit 1
fi

openssl ecparam -outform PEM -out test.param -name secp521r1 
openssl req -x509 -newkey ec:$1.param -keyform PEM -keyout $1.key -outform PEM -days 365 -out $1.crt
exit 0
