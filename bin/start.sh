#!/usr/bin/env bash
. etc/config.py

echo "Starting server at port: $port"
#nohup ./myprogram.sh > /dev/null 2>&1 & echo $! > run.pid
nohup ./httpd.py > $web_logfile 2>&1 & echo $! > $session_dir/$meta_name.pid
#nohup ./httpd.py > $web_logfile &
