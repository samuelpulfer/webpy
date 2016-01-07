#!/usr/bin/env bash

cfg_file="./etc/config.py"
. "$cfg_file"

# remove temp files
find ./ -iname "*.pyc" -exec rm {} \;
find ./ -iname "*~" -exec rm {} \;

# remove libs
rm -rf lib/wsgilog-0.3
rm -rf lib/web.py-0.37
rm -rf static/ext-5.1.1
rm -rf static/bootstrap-3.3.5-dist
rm -rf "$session_dir/$session_prefix"*

rm -r lib/web
rm -r lib/wsgilog
