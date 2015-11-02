#!/usr/bin/env python

# setup paths
import os, sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'etc'))
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'lib'))
import config

import sqlite3 as lite
import sys
import hashlib

_con = None
_cur = None

def get_conn():
	global _con
	global _cur
	
	if _con:
		return (_con, _cur)
	
	try:
		_con = lite.connect(config.user_db)
		_cur = _con.cursor()	
		return (_con, _cur)
	
	except lite.Error, e:
		print "Error %s:" % e.args[0]
		sys.exit(1)

def usage():
	return "usage: <user> <pass>"

if __name__ == "__main__":
	"""
	Create or modify system user.
	
	Parameters expected:
	 - username
	 - password
	"""
	
	# check parameters
	if len(sys.argv) != 3:
		print usage()
		sys.exit(1)
	
	username = sys.argv[1]
	password = sys.argv[2]
	#print username, password
	
	# get db connection
	con, cur = get_conn()
	
	# check if user exists
	sql = "SELECT id FROM user WHERE username='"+username+"'"
	
	res = con.execute(sql)
	found = False
	for row in res:
		#print "ID =", row[0]
		found = True
	
	# if we have found the username, modify it
	if found == True:
		cur.execute("UPDATE user SET password='%s' WHERE username='%s'" % \
		           (hashlib.md5(password).hexdigest(), username))
		con.commit()		
		
	# else create a new user
	else:
		cur.execute("INSERT INTO user (username, password) VALUES ('%s', '%s')" % \
		           (username, hashlib.md5(password).hexdigest()))
		con.commit()		

