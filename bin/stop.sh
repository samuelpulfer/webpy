#!/usr/bin/env bash

#for p in `pgrep -f httpd.py`; do
#	kill -TERM $p
#done

. etc/config.py
if [[ -f "$session_dir/$meta_name.pid" ]]; then
	kill -TERM `cat "$session_dir/$meta_name.pid"`
	rm "$session_dir/$meta_name.pid"
	rm -R var/session_* >> /dev/null 2>&1
fi
