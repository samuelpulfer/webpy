#!/usr/bin/env bash

cfg_file="./etc/config.py"
. "$cfg_file"

function set_config() {
	key="$1"
	value="$2"
	file="$3"
	quote="$4"
	
	if [[ "$quote" == "" ]]; then
		sed -i -e 's/'"$key"'=.*/'"$key"'='"$value"'/;' "$file"
	else
		sed -i -e 's/'"$key"'=.*/'"$key"'="'"$value"'"/;' "$file"
	fi
}

echo "Setting up defaults ..."
uuid=`./bin/genuuid.py`
uuid=`echo -n $uuid`
echo "==> session salt: $uuid"
#sed -i -e 's/session_salt=.*/session_salt="'$uuid'"/;' etc/config.py
set_config "session_salt" "$uuid" "etc/config.py" true
read -p "Set application name [$meta_name]: " new_meta_name
if [[ "$new_meta_name" != "" && "$new_meta_name" != "$meta_name" ]]; then
	set_config "meta_name" "$new_meta_name" "etc/config.py" true
fi
read -p "Set application version [$meta_version]: " new_meta_version
if [[ "$new_meta_version" != "" && "$new_meta_version" != "$meta_version" ]]; then
	set_config "meta_version" "$new_meta_version" "etc/config.py" true
fi
read -p "Set port [$port]: " newport
if [[ "$newport" != "" && "$newport" != "$port" ]]; then
	set_config "port" "$newport" "etc/config.py"
fi

newuser=""
newpass=""
function username() {
	read -p "Set admin user name [admin]: " newuser
	
	if [[ "$newuser" == "" ]]; then
		newuser="admin"
	fi
	return 1
}
while username; do a=1; done

function pass() {
	read -p "Set admin password: " newpass
	
	if [[ "$newpass" == "" ]]; then
		return 0
	else
		return 1
	fi
}
while pass; do a=1; done
echo "Creating new user '$newuser' ..."
./bin/setuser.py "$newuser" "$newpass"
#echo "$newpass" | hexdump

read -p "Hit any key to extract files." tmp

echo "Unpacking libraries ..."
cd lib

tar xzf web.py-0.37.tar.gz
ln -s web.py-0.37 web

tar xjf wsgilog-0.3.tar.bz2 
ln -s wsgilog-0.3 wsgilog

unzip bootstrap-3.3.5-dist.zip -o -d ../static/

cd ..
cd static

unzip -o ext-5.1.1-gpl.zip
ln -s ext-5.1.1 ext

cd ..


