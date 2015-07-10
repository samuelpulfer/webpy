session = None


## page methods ################################################################

class webctx(object):
	session = None
	no_auth = False
	__authenticated = False
	def auth_check(self):
		""" check if user is authenticated """
		
		"""
		try:
			webctx.session.uid
		except:
			web.debug("creating session")
			for e in session_default:
				webctx.session[e] = session_default[e]
		"""
		
		#webctx.session = get_session()
		
		# check if we have a valid session
		if webctx.session != None and webctx.session.uid > 0:
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
	no_auth = True
	
	def GET(self):
		#global webctx.session
	
		user_data = web.input(logout=False)
		web.debug(user_data.logout)
		if (user_data.logout == "true"):
			#webctx.session = session_default
			webctx.session.kill()
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
				#webctx.session = session_default
				webctx.session.uid = row[0]
				webctx.session.user = username
			
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
			#webctx.session = session_default
			webctx.session.uid = emp["employeeNumber"]
			webctx.session.user = username
			webctx.session.email = emp["email"]
			return '{"success": true}'
		
		return '{"success": false}'

class index(webctx):
	""" Serve index page """
	def GET(self):
		if not self.auth_check():
			return self.render().login()
			
		#web.debug(auth_check)
		#web.debug(webctx.session)
		
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

