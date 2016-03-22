function send_form() {
	// get data from the form
	var tgturi = document.getElementById("tgturi").value;
	var message = document.getElementById("message").value;
	

	
	var r = new XMLHttpRequest();
	r.open("POST", tgturi, true);
	r.setRequestHeader("Content-Type","application/json; charset=utf-8");
	r.onreadystatechange = function () {
		switch (r.readyState) {
			case 0:
				document.getElementById('info').innerHTML = 'request not initialized. Status: ' + r.statusText;
				break;
			case 1:
				document.getElementById('info').innerHTML = 'server connection established. Status: ' + r.statusText;
				break;
			case 2:
				document.getElementById('info').innerHTML = 'request received. Status: ' + r.statusText;
				break;
			case 3:
				document.getElementById('info').innerHTML = 'processing request. Status: ' + r.statusText;
				break;
			case 4:
				document.getElementById('info').innerHTML = 'request finished and response is ready. Status: ' + r.statusText;
				break;
		}
		if (r.readyState==4 && r.status==200) {
			//console.log(data)
			data = JSON.parse(r.responseText);
			document.getElementById("response").innerHTML = JSON.stringify(data);
			return
		};
	};
	r.send(JSON.stringify(message));
}
