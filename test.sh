#!/bin/bash -ex

trap "kill 0" SIGINT

#### Default Configuration

CONCURRENCY=10000
REQUESTS=1
ADDRESS="http://localhost:8000/"
PROCESSES=$(nproc)/2
NAME=webserver_liburing
TIME_OUT=120
REQUEST_TIMEOUT=60
WRK=0

show_help() {
cat << EOF
Naive Stress Test with cURL.
Usage: ./stress-test.sh [-a ADDRESS] [-c CONCURRENCY] [-r REQUESTS]
Params:
  -a  address to be tested.
      Defaults to localhost:8080
  -c  conccurency: how many process to spawn
      Defaults to 1
  -r  number of requests per process
      Defaults to 10
  -h  show this help text
Example:
  $ ./stress-test.sh -c 4 -p 100 (400 requests to localhost:8080)
EOF
}


#### CLI

while getopts ":a:c:r:n:p:t:w:o:h" opt; do
  case $opt in
    a)
      ADDRESS=$OPTARG
      ;;
    c)
      CONCURRENCY=$OPTARG
      ;;
    r)
      REQUESTS=$OPTARG
      ;;
    n)
      NAME=$OPTARG
      ;;
    p)
      PROCESSES=$OPTARG
      ;;
    t)
      TIME_OUT=$OPTARG
      ;;
    w)
      WRK=$OPTARG
      ;;
    o)
      REQUEST_TIMEOUT=$OPTARG
      ;;
    h)
      show_help
      exit 0
      ;;
    \?)
      show_help >&2
      echo "Invalid argument: $OPTARG" &2
      exit 1
      ;;
  esac
done

shift $((OPTIND-1))

#### Main

for i in `seq 1 $PROCESSES`; do
  let PORT=8000+i
  if [ "$WRK" -ne 0 ]
  then
    wrk -t$WRK -c$CONCURRENCY -d${TIME_OUT}s --latency --timeout=${REQUEST_TIMEOUT}s http://127.0.0.1:$PORT/index.html & pidlist="$pidlist $!"
  else
    let TOTALREQUESTS=$CONCURRENCY*$REQUESTS
    ab -t ${TIME_OUT} -s ${REQUEST_TIMEOUT} -c $CONCURRENCY -n $TOTALREQUESTS http://localhost:$PORT/index.html & pidlist="$pidlist $!"
  fi
done

# Execute and wait
FAIL=0
for job in $pidlist; do
  echo $job
  wait $job || let "FAIL += 1"
done

# Verify if any failed
if [ "$FAIL" -eq 0 ]; then
  echo "SUCCESS!"
else
  echo "Failed Requests: ($FAIL)"
fi

