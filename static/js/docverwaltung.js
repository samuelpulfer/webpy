function send_form(obj) {
	// get data from the form
	var message = parseInt(document.getElementById("message").value);
	
	// display the values gathered fro mthe form
	console.log(message);
	
	var r = new XMLHttpRequest();
	r.open("POST", "/docverwaltung", true);
	r.setRequestHeader("Content-Type","application/json; charset=utf-8");
	r.onreadystatechange = function () {
		switch (r.readyState) {
			case 0:
				break;
			case 1:
				break;
			case 2:
				break;
			case 3:
				break;
			case 4:
				break;
		}
		if (r.readyState==4 && r.status==200) {
			//console.log(data)
			data = JSON.parse(r.responseText);
			console.log(data)
			document.getElementById("response").innerHTML = JSON.stringify(data);
			return
		};
	};
	var params = document.getElementById("message").value;
	r.send(JSON.stringify(params));
}
