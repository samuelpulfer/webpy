function byId(id) {return document.getElementById(id);}
function log_status(txt) {
	document.getElementById('info').innerHTML = txt;
}

function auth() {
	var params = {
		username: byId("username").value,
		password: byId("password").value
	};
	
	var r = new XMLHttpRequest();
	r.open("POST", "/login", true);
	r.setRequestHeader("Content-Type","application/json; charset=utf-8");
	r.onreadystatechange = function () {
		switch (r.readyState) {
			case 0:
				log_status('request not initialized. Status: ' + r.statusText);
				break;
			case 1:
				log_status('server connection established. Status: ' + r.statusText);
				break;
			case 2:
				log_status('request received. Status: ' + r.statusText);
				break;
			case 3:
				log_status('processing request. Status: ' + r.statusText);
				break;
			case 4:
				log_status('request finished and response is ready. Status: ' + r.statusText);
				break;
		}
		
		if (r.readyState == 4 && r.status == 200) {
			data = JSON.parse(r.responseText);
			console.log(data)
			if (data.error == 1) {
				log_status('Response contains an error.')
			}
			
			if (data.success == true)
				// reload page
				document.location.href = document.location.href
			
			byId('password').value = ''
			log_status("Unknown username and/or password, try again.")
			return
		}
	}
	r.send(JSON.stringify(params));
}
