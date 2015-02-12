#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Start application server on port 8080

The first command line argument will set the port to be bound. Remeber, you 
need root privvileges to bind ports below 1024.

"""

import os, sys
sys.path.append(os.path.join(os.path.dirname(__file__), 'etc'))
sys.path.append(os.path.join(os.path.dirname(__file__), 'lib'))
sys.path.append(os.path.join(os.path.dirname(__file__), 'lib', 'web'))

import web, config, json
import datetime
import time
import tempfile
import sys, logging
from wsgilog import WsgiLog

urls = (
  '/', 'index',
  '/env', 'env',
)

session_default = {
	"user": None
}

# allow to pass a custom port/ip into the application
class service(web.application):
	def run(self, port=8080, ip='0.0.0.0', *middleware):
		func = self.wsgifunc(*middleware)
		return web.httpserver.runsimple(func, (ip, port))

class Log(WsgiLog):
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

class index:
	def GET(self):
		render = web.template.render('template')
		return render.index()
		#return out

class env:
	def GET(self):
		out = {}
		for property, value in vars(web.ctx).iteritems():
			out[property] = value
		
		render = web.template.render('template', globals={'is_dict': is_dict})
		return render.env(out)
		#return out

def is_dict(d):
	return type(d) is dict

if __name__ == "__main__":

	# redirect webserver logs to file
	#weblog = open(config.web_logfile, "ab")
	#sys.stderr = weblog
	#sys.stdout = weblog
	
	app = service(urls, globals())
	
	# session setup, make sure to call it only one if in debug mode
	if web.config.get('_session') is None:
		web.config.session_parameters['cookie_name'] = config.session_name
		web.config.session_parameters['cookie_domain'] = None
		web.config.session_parameters['timeout'] = config.session_timeout,
		web.config.session_parameters['ignore_expiry'] = True
		web.config.session_parameters['ignore_change_ip'] = False
		web.config.session_parameters['secret_key'] = config.session_salt
		web.config.session_parameters['expired_message'] = 'Session expired'
	
		temp = tempfile.mkdtemp(dir=config.session_dir, prefix='session_')
		web.sess = web.session.Session(
			app, 
			web.session.DiskStore(temp), 
			initializer = session_default
		)
	else:
		web.sess = web.config._session
		try:
			web.sess["pid"]
		except:
			web.sess = session_default
	#web.sess["pid"] += 1
	#print "starting ..."
	#app.add_processor(web.loadhook(loadhook))
	#app.add_processor(web.unloadhook(unloadhook))
	app.run(config.port, "0.0.0.0", Log)
	
