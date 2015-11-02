# webpy

## Installation

    git clone https://github.com/wunderlins/webpy.git
    ./bin/setup.sh


## Run
    $ cd projectdir
    $ . ./lib/setenv.sh
    $ start # can be run from any directory or
    $ <path to rootdir>/bin/start.sh # can be run from any directory
    dito stop
    $ help # for a list of commands


## Development
  - use ./bin/clean.sh to remove all extracted libraries and session/temp files (does not remove etc/user.db, subsequent calls to setup.sh will update existing users)
  - use ./bin/setup.sh to create a new installation
  - use . ./lib/setenv.sh to setup helper scripts for administration, these provide
    the following commands: help, start, stop, restart, status

## Dependencies
  - gcc
  - python uuid
