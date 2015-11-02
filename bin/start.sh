#!/usr/bin/env bash

export basedir=`dirname ${BASH_SOURCE[0]}`"/.."
basedir=`$basedir/bin/realpath $basedir`
cd "$basedir"

. $basedir/etc/config.py

echo "Starting server at port: $port"
#nohup ./myprogram.sh > /dev/null 2>&1 & echo $! > run.pid
nohup $basedir/httpd.py > $basedir/$web_logfile 2>&1 & echo $! > $basedir/$session_dir/$meta_name.pid
#nohup ./httpd.py > $web_logfile &
