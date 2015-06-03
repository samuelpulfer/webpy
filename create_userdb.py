#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Create a sample sqlite user database
"""

import sqlite3 as lite
import sys
import hashlib

con = None
cur = None

def get_conn():
	global con
	global cur
	
	if con:
		return con
	
	try:
		con = lite.connect('etc/user.db')
		cur = con.cursor()	
		return con
	
	except lite.Error, e:
		print "Error %s:" % e.args[0]
		sys.exit(1)
		
		"""		
		cur.execute('SELECT SQLITE_VERSION()')
		data = cur.fetchone()
		print "SQLite version: %s" % data				
		"""

def create(username, password):
	global con
	global cur
	
	get_con()
	cur.execute("INSERT INTO user (username, password) VALUES ('%s', '%s')") % \
	           (username, hashlib.md5(password).hexdigest())
	

"""
except lite.Error, e:
	
	print "Error %s:" % e.args[0]
	sys.exit(1)
	
finally:
	
	if con:
		con.close()
"""
