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

# import modules
import web, config, json
import datetime
import time
import tempfile
import sys, logging
from wsgilog import WsgiLog
from cgi import escape

## global variables ############################################################

# url to class mapping
urls = (
  '/', 'index',
  '/env', 'env',
  '/json', 'json',
)

# default session values
session_default = {
	"user": None
}

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

## page methods ################################################################
class index:
	""" Serve index page """
	def GET(self):
		render = web.template.render('template')
		return render.index()
		#return out

class env:
	""" display environment variables """
	def GET(self):
		out = {}
		for property, value in vars(web.ctx).iteritems():
			out[property] = value
		
		render = web.template.render('template', globals={'is_dict': is_dict, 'escape': escape})
		return render.env(out)
		#return out

class json:
	""" Serve json example page """
	def GET(self):
		render = web.template.render('template')
		return render.json()
		#return out
	
	def POST(self):
		post = web.input()
		web.header('Content-Type', 'application/json')
		try:
			i1 = int(post.int1)
			i2 = int(post.int2)
			res = i1 + i2
		except:
			return "{error: 1}"
		
		return '{"i1": '+str(i1)+', "i2": '+str(i2)+', "res": '+str(res)+'}'

def is_dict(d):
	""" additional template function, registered with web.template.render """
	return type(d) is dict

## main function ###############################################################
if __name__ == "__main__":

	# redirect webserver logs to file
	#weblog = open(config.web_logfile, "ab")
	#sys.stderr = weblog
	#sys.stdout = weblog
	
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
	
