#!/usr/bin/env bash

system=""
uname -v | grep "Darwin" >/dev/null 2>&1
if [[ $? == 0 ]]; then system="Darwin"; fi
uname -v | grep "Debian" >/dev/null 2>&1
if [[ $? == 0 ]]; then system="Debian"; fi

export system
export basedir=`dirname ${BASH_SOURCE[0]}`"/.."
export PATH=$PATH:$basedir/bin
basedir=`realpath $basedir`

if [[ -n $0 && "$0" != "-bash" ]]; then
	script=`basename $0`
else
	script=""
fi

alias gd='git diff | colordiff | less -R'
alias ls='ls --color'

#if [[ `hostname` == "sranawebln01" ]]; then
#	export cfg_file="config-sranawebln01.py"
#else
#	export cfg_file="config-dev.py"
#fi
export cfg_file="config.py"

. $basedir/etc/$cfg_file

PS1="<\[\033[31m\]\h\[\033[0m\]:\[\033[36m\]$meta_name\[\033[0m\]> \[\033[34m\]\W\[\033[0m\]\[\033[37m\]%\[\033[0m\] "

function variables() {
	echo "Using cfg              : $cfg_file"
	echo "Name                   : $meta_name"
	echo "Version                : $meta_version"
	echo "System                 : $system"
	echo ""
	echo "Basedir                : $basedir"
	echo ""
}

function start() {
	$basedir/bin/start.sh
}

function stop() {
	$basedir/bin/stop.sh
}

function restart() {
	$basedir/bin/restart.sh
}

function status() {
	variables
	$basedir/bin/status.sh
}

function reload() {
	. $basedir/lib/setenv.sh
}

alias bash_help="bash -c 'help'"

function help() {
	cat << EOT
Usage: $script

start
	start daemon

stop
	stop daemon

restart
	restart daemon

status
	check if running.
	Returns 0 if not running, else 1

reload
	reload configuration

rebuild
	clears and rebuilds the thumbnail cache on disk.

NOTE: The bash's builtin help is now available as 'bash_help'.


ENVIRONMENT VARIABLES

EOT

variables
}

#echo $basedir
