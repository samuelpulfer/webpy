#!/usr/bin/env python
# -*- coding: utf-8 -*-

import web, config, json
import datetime
import time
import re
import base64
import sys
import os
import usbauth
import hashlib
import sqlite3
import testinterface
import docrest
import pprint
import mimerender
import dicttoxml
from xml.dom.minidom import parseString

session = None

def is_dict(d):
	""" additional template function, registered with web.template.render """
	return type(d) is dict

class status(web.HTTPError):
	""" custom http error handler """
	http_codes = {	
		'100': 'Continue', '101': 'Switching Protocols',
		'200': 'OK', '201': 'Created', '202': 'Accepted',
				'203': 'Non-Authoritative Information','204': 'No Content',
				'205': 'Reset Content', '206': 'Partial Content', 
		'300': 'Multiple Choices', '301': 'Moved Permanently', '302': 'Found',
				'303': 'See Other', '304': 'Not Modified', '305': 'Use Proxy',
				'306': '(Unused)', '307': 'Temporary Redirect', 
		'400': 'Bad Request', '401': 'Unauthorized', '402': 'Payment Required',
				'403': 'Forbidden', '404': 'Not Found', '405': 'Method Not Allowed',
				'406': 'Not Acceptable', '407': 'Proxy Authentication Required',
				'408': 'Request Timeout', '409': 'Conflict', '410': 'Gone',
				'411': 'Length Required', '412': 'Precondition Failed',
				'413': 'Request Entity Too Large', '414': 'Request-URI Too Long',
				'415': 'Unsupported Media Type', '416': 'Requested Range Not Satisfiable',
				'417': 'Expectation Failed',
		'500': 'Internal Server Error', '501': 'Not Implemented',
				'502': 'Bad Gateway', '503': 'Service Unavailable', 
				'504': 'Gateway Timeout', '505': 'HTTP Version Not Supported'
	}
	
	def _http_code_lookup(self, code):
		out = None
		try:
			out = self.http_codes[str(code)]
			out = str(code) + " " + out
		except:
			out = "520 Unknown Error"
		
		return out
	
	code = None
	status = None
	headers = None
	
	def __init__(self, code, data=None, headers=None):
		self.code = code
		self.headers = {'Content-Type': 'text/html'}
		self.status = self._http_code_lookup(code)
		self.data = "<h1>" + str(self.status) + "</h1>"
		
		if headers != None:
			self.headers = headers
		if data != None:
			self.data = data
		
	def fail(self):
		web.debug(self.status)
		web.debug(self.headers)
		web.debug(self.data)
		web.HTTPError.__init__(self, self.status, self.headers, self.data)

# mimerender
mimerender = mimerender.WebPyMimeRender()

class renderer(object):
	
	@staticmethod
	def dict2xml(d):
		return parseString(dicttoxml.dicttoxml(d, \
		                   custom_root="root")).toprettyxml()
	
	@staticmethod
	def dict2json(d):
		return json.dumps(d)
	
	@staticmethod
	def dict2txt(d):
		pp = pprint.PrettyPrinter(indent=4, width=1)
		return pp.pformat(d)
	
	@staticmethod
	def dict2html(d):
		buffer = '<table border="1" style="border-collapse: collapse;"><tbody>'
		for e in d:
			buffer += "<tr><td>" + str(e) + "</td><td>"
			if type(d[e]) is dict: # or type(d[e]) is list:
				buffer += renderer.dict2html(d[e])
			else:
				buffer += str(d[e])
			buffer += "</td></tr>"
		buffer += '</tbody></table>'
	
		return buffer
		
## page methods ################################################################

class webctx(object):
	session = None
	no_auth = False
	__authenticated = False
	def auth_check(self):
		""" check if user is authenticated """
		
		"""
		try:
			session.uid
		except:
			web.debug("creating session")
			for e in session_default:
				session[e] = session_default[e]
		"""
		
		#session = get_session()
		
		# check if we have a valid session
		if session != None and session.uid > 0:
			self.__authenticated = True
			return True
		
		# authentication for this request not required
		if self.no_auth == True:
			return True
			
		# check if the user has submitted credentials
		return None
	
	def render(self):
		return web.template.render('template', globals={
			'is_dict': is_dict
		})
	
	def error(self, code):
		st = status(code)
		content = self.render().error(code, st.status, "sss")
		st.fail()

class login(webctx):
	no_auth = True
	
	def GET(self):
		#global session
	
		user_data = web.input(logout=False)
		web.debug(user_data.logout)
		if (user_data.logout == "true"):
			#session = session_default
			session.kill()
			raise web.seeother('/')
	
	""" authenticate user """
	def POST(self):
		
		# read posted json data
		data = web.data()
		credentials = json.loads(data)
	
		username = credentials["username"]
		password = credentials["password"]
		
		# check credentials against database
		pwhash = hashlib.md5(password).hexdigest()
		web.debug(pwhash)
		authdb = sqlite3.connect('etc/user.db')
		cur = authdb.cursor()
		sql = 'SELECT id FROM user WHERE username=? AND password=?'
		web.debug(sql)
		check = cur.execute(sql, (username, pwhash))
		web.debug(str(check) + " " + str(cur.rowcount))
		
		if check:
			row = cur.fetchone()
			if row:
				authdb.close()
				web.debug(row)
				#session = session_default
				session.uid = row[0]
				session.user = username
			
				# if we found one, exit
				return '{"success": true}'
		
		authdb.close()
		
		# if not found check against ldap
		usbauth.init(
			authdn = "CN=MUANA,OU=GenericMove,OU=Users,OU=USB,DC=ms,DC=uhbs,DC=ch",
			authpw = "anaana",
			baseDN = "ou=USB,dc=ms,dc=uhbs,dc=ch",
			host = "ms.uhbs.ch",
		)
		
		emp = usbauth.check(username, password)
		if (emp and emp["lockoutTime"] == None):
			#session = session_default
			if emp["employeeNumber"]:
				session.uid = emp["employeeNumber"]
			else:
				session.uid = "123456"
			session.user = username
			session.email = emp["email"]
			return '{"success": true}'
		
		return '{"success": false}'

class index(webctx):
	""" Serve index page """
	def GET(self):
		if not self.auth_check():
			return self.render().login()
			
		#web.debug(auth_check)
		#web.debug(session)
		
		render = web.template.render('template')
		return render.index()
		#return out

class bootstrap(webctx):
	""" Serve bootstrap example page """
	def GET(self):
		if not self.auth_check():
			return self.render().login()
			
		#web.debug(auth_check)
		#web.debug(session)
		
		render = web.template.render('template')
		return render.bootstrap()
		#return out
		
class image(webctx):
	no_auth = True
	""" Serve image, this method requires not authentication """
	def GET(self):
		filename = "static/py.png"
		web.header('Content-Type', 'image/png')
		web.header('Content-Length', os.path.getsize(filename))
		import datetime
		t = datetime.datetime.fromtimestamp(os.path.getmtime(filename))
		#strdate = t.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
		web.http.lastmodified(t)
		fp = open(filename, "r")
		yield fp.read()
		fp.close()
		
		return

class env(webctx):
	""" display environment variables """
	def GET(self):
		if not self.auth_check():
			return self.render().login()
		
		out = {}
		for property, value in vars(web.ctx).iteritems():
			out[property] = value
		
		return self.render().env(out)

class json1(webctx):
	""" Serve json example page (using JQuery)"""
	def GET(self):
		if not self.auth_check():
			return self.render().login()
			
		#render = web.template.render('template')
		return self.render().json1()
		#return out
	
	def POST(self):
		if not self.auth_check():
			return self.render().login()
		
		post = web.input()
		web.header('Content-Type', 'application/json')
		try:
			i1 = int(post.int1)
			i2 = int(post.int2)
			res = i1 + i2
		except:
			return '{"error": 1}'
		
		return '{"error": 0, "i1": '+str(i1)+', "i2": '+str(i2)+', "res": '+str(res)+'}'
		
class json2(webctx):
	""" Serve json example page (100% VanillaJS)"""
	def GET(self):
		if not self.auth_check():
			return self.render().login()
		
		render = web.template.render('template')
		return render.json2()
	
	def POST(self):
		if not self.auth_check():
			return self.render().login()
		
		web.header('Content-Type', 'application/json')
		try:
			post = json.loads(web.data())
			i1 = int(post["int1"])
			i2 = int(post["int2"])
			res = i1 + i2
			print str(res)
		except:
			return '{"error": 1}'
		
		return '{"error": 0, "i1": '+str(i1)+', "i2": '+str(i2)+', "res": '+str(res)+'}'

class authorisationxmpl(webctx):
	def GET(self):
		if not self.auth_check():
			return self.render().login()

		if usbauth.authorisation(session.user, "MT_P_mtwikilp01_statistics_pneumo"):
			message = "Sie sind in der Gruppe MT_P_mtwikilp01_statistics_pneumo"
		else:
			message = "Sie sind NICHT in der Gruppe MT_P_mtwikilp01_statistics_pneumo"
			
		render = web.template.render('template')
		return render.authxmpl(message)

		
class docverwaltung(webctx):
	""" Countdown page (100% VanillaJS)"""
	def GET(self):
		no_auth = True
		
		render = web.template.render('template')
		return render.docverwaltung()
	
	def POST(self):
		web.header('Content-Type', 'application/json')
		try:
			post = json.loads(web.data())
			post = json.loads(post)
		except:
			return '{ "meta": {"error": 1, "error_message": "no valid json received", "version": "0.0.1"}}'
		
		#return post
		return json.dumps(testinterface.dosomething(post))

class resttest(webctx):
	def GET(self):
		render = web.template.render('template')
		return render.resttest()
		
class rest(webctx):
	render_xml  = lambda **args: renderer.dict2xml(args)
	render_json = lambda **args: renderer.dict2json(args)
	render_html = lambda **args: '<!DOCTYPE html>\n<html>\n<body>\n' + \
	                             renderer.dict2html(args) + "\n</body>\n</html>"
	render_txt  = lambda **args: renderer.dict2txt(args)
	
	@mimerender(
		default = 'json',
		#html = render_html,
		json = render_json,
		xml  = render_xml,
		txt  = render_txt
	)
	def GET (self, name):
		web.header('Access-Control-Allow-Origin',      '*')
		web.header('Access-Control-Allow-Credentials', 'true')
		if not name: 
			name = 'world'
		data = {
			'message': 'Hello, ' + name + '!', 
			"sub": {
				"array": [1,2,3], 
				"list": {"a": 1, "b": 2}
			}
		}
		return data
		
	@mimerender(
		default = 'json',
		json = render_json
	)
	def POST(self, name):
		web.header('Access-Control-Allow-Origin',      '*')
		web.header('Access-Control-Allow-Credentials', 'true')
		data = json.loads(web.data())
		print name
		print data
		#WTF ???
		#data = json.loads(data)
		if name == "":
			return testinterface.dosomething(data)
		else:
			return docrest.doit(data, name)
			#response = dict(path=dict(),message=dict())
			#response['message'] = data
			#response['path'] = name
			#return response
			
	def OPTIONS(self, name):
		web.header('Access-Control-Allow-Origin',      '*')
		web.header('Access-Control-Allow-Credentials', 'true')
		web.header('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
		web.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept')
		
