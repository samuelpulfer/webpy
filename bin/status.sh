#!/usr/bin/env bash

basedir="`cd $(dirname $0)/..;pwd`"; cd "$basedir"
. $basedir/lib/setenv.sh

ret=`netstat -anlt | grep $port | grep -v TIME_WAIT`
if [[ $? == 0 ]]; then
	echo "port $port is bound."
	exit 1
fi

echo "port is NOT bound, service not running."

exit 0

#if [[ "$server" == "dev" ]]; then
#	echo "TODO status.sh dev"
#fi

#if [[ "$server" == "uwsgi" ]]; then
#	echo "TODO: status.sh uwsgi"
#fi
