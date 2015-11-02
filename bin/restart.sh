#!/usr/bin/env bash

export basedir=`dirname ${BASH_SOURCE[0]}`"/.."
basedir=`$basedir/bin/realpath $basedir`

$basedir/bin/stop.sh
$basedir/bin/start.sh
