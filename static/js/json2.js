function send_form(obj) {
	// get data from the form
	var int1 = parseInt(document.getElementById("int1").value);
	var int2 = parseInt(document.getElementById("int2").value);
	
	// display the values gathered fro mthe form
	console.log(int1 + " " + int2);
	
	// user input sanity check
	if (isNaN(int1)) {
		alert("«int1» is not a number");
		return false;
	}
	
	if (isNaN(int2)) {
		alert("«int2» is not a number");
		return false;
	}
	
	// create a json request object
	var params = {
		int1: int1,
		int2: int2
	}
	
	var r = new XMLHttpRequest();
	r.open("POST", "/json2", true);
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
			if (data.error == 1) {
				document.getElementById('info').innerHTML = 'Response contains an error.'
			}
			document.getElementById("result").innerHTML = 
				data.i1 + " <em>and</em> " + data.i2 + " <em>equals</em> " + data.res;
			return
		};
	};
	r.send(JSON.stringify(params));
}
