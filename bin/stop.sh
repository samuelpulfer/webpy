#!/usr/bin/env bash

export basedir=`dirname ${BASH_SOURCE[0]}`"/.."
basedir=`$basedir/bin/realpath $basedir`

. $basedir/etc/config.py

if [[ -f "$basedir/$session_dir/$meta_name.pid" ]]; then
	kill -TERM `cat "$basedir/$session_dir/$meta_name.pid"`
	rm "$basedir/$session_dir/$meta_name.pid"
	rm -R $basedir/var/session_* >> /dev/null 2>&1
fi
