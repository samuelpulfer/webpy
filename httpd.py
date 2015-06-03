#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Start application server on port 8080

The first command line argument will set the port to be bound. Remeber, you 
need root privvileges to bind ports below 1024.

"""

# setup paths
import os, sys
sys.path.append(os.path.join(os.path.dirname(__file__), 'etc'))
sys.path.append(os.path.join(os.path.dirname(__file__), 'lib'))
sys.path.append(os.path.join(os.path.dirname(__file__), 'lib', 'web'))
sys.path.append(os.path.join(os.path.dirname(__file__), 'lib', 'wsgilog'))

# import modules
import web, config, json
import datetime
import time
import tempfile
import sys, logging
from wsgilog import WsgiLog
from cgi import escape
import usbauth

## global variables ############################################################

# url to class mapping
urls = (
  '/', 'index',
  '/env', 'env',
  '/json1', 'json1',
  '/json2', 'json2',
  '/image', 'image',
  '/login', 'login'
)

# default session values
session_default = {
	"uid": -1,
	"user": None
}
web_session = None

## webpy extensions ############################################################

class service(web.application):
	""" allow to pass a custom port/ip into the application """
	def run(self, port=8080, ip='0.0.0.0', *middleware):
		func = self.wsgifunc(*middleware)
		return web.httpserver.runsimple(func, (ip, port))

class Log(WsgiLog):
	""" extend logger, logging to file in var/ """
	def __init__(self, application):
		WsgiLog.__init__(
			self,
			application,
			logformat = '%(message)s',
			tofile = True,
			toprint = True,
			file = config.app_logfile,
			#when = "D",
			#interval = 1,
			#backups = "1000"
		)

class hooks(object):
	@staticmethod
	def load():
		web.debug("Loadhook")
		#return "BEGIN"
	
	@staticmethod
	def unload():
		web.debug("Unloadhook")
		#return "ENDE"

## page methods ################################################################

class webctx(object):
	no_auth = False
	__authenticated = False
	def auth_check(self):
		""" this is the base class for all methods, that need authentication
		
		authentication works as follows:
		- check user identity against ldap
		- if user exists, check if we have him/her in our userdatabase
			- if not add it
		- fetch additional user data from database
		- setup session with gathered information
		
		"""
		web.debug("auth_check")
		
		# check if we have a valid session
		if web_session != None and web_session["uid"] > 0:
			self.__authenticated = True
			return True
		
		# authentication for this request not required
		if self.no_auth == True:
			return True
			
		# check if the user has submitted credentials
		return None
		
		
	def render(self):
		return web.template.render('template', globals={
			'is_dict': is_dict, 
			'escape': escape
		})
		

class login(webctx):
	def POST(self):
		data = web.data()
		credentials = json.loads(data)
		#web.debug(credentials)
		
		username = credentials["username"]
		password = credentials["password"]
		
		web.debug(username)
		web.debug(password)
		
		# check credentials against database
		
		
		return '{"success": true}'


class index(webctx):
	""" Serve index page """
	def GET(self):
		if not self.auth_check():
			return self.render().login()
			
		web.debug(auth_check)
		#web.debug(web_session)
		
		render = web.template.render('template')
		return render.index()
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
		out = {}
		for property, value in vars(web.ctx).iteritems():
			out[property] = value
		
		return self.render().env(out)

class json1(webctx):
	""" Serve json example page (using JQuery)"""
	def GET(self):
		#render = web.template.render('template')
		return self.render().json1()
		#return out
	
	def POST(self):
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
		render = web.template.render('template')
		return render.json2()
	
	def POST(self):
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

def is_dict(d):
	""" additional template function, registered with web.template.render """
	return type(d) is dict

## main function ###############################################################
if __name__ == "__main__":

	# redirect webserver logs to file
	#weblog = open(config.web_logfile, "ab")
	#sys.stderr = weblog
	#sys.stdout = weblog
	
	usbauth.init(
		authdn = "CN=MUANA,OU=GenericMove,OU=Users,OU=USB,DC=ms,DC=uhbs,DC=ch",
		authpw = "anaana",
		baseDN = "ou=USB,dc=ms,dc=uhbs,dc=ch",
		host = "ms.uhbs.ch",
	)
	
	app = service(urls, globals())
	
	# session setup, make sure to call it only once if in debug mode
	if web.config.get('_session') is None:
		web.config.session_parameters['cookie_name'] = config.session_name
		web.config.session_parameters['timeout'] = config.session_timeout,
		web.config.session_parameters['secret_key'] = config.session_salt
		web.config.session_parameters['cookie_domain'] = config.session_cookie_domain
		web.config.session_parameters['ignore_expiry'] = config.session_ignore_expiry
		web.config.session_parameters['ignore_change_ip'] = config.session_ignore_change_ip
		web.config.session_parameters['expired_message'] = config.session_expired_message
	
		temp = tempfile.mkdtemp(dir=config.session_dir, prefix='session_')
		web_session = web.session.Session(
			app, 
			web.session.DiskStore(temp), 
			initializer = session_default
		)
	else:
		web_session = web.config._session
		try:
			web_session["uid"]
		except:
			web_session = session_default
	
	app.add_processor(web.loadhook(hooks.load))
	app.add_processor(web.unloadhook(hooks.unload))
	
	web.config.debug = True
	
	#web_session["pid"] += 1
	#print "starting ..."
	#app.add_processor(web.loadhook(loadhook))
	#app.add_processor(web.unloadhook(unloadhook))
	#app.run(config.port, "0.0.0.0")
	app.run(config.port, "0.0.0.0", Log)


