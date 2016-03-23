function byId(elid) {return document.getElementById(elid);}

function send_form(data, path, action) {	
	var r = new XMLHttpRequest();
	r.open("POST", path, true);
	r.setRequestHeader("Content-Type","application/json; charset=utf-8");
	r.onreadystatechange = function () {
		if (r.readyState==4 && r.status==200) {
			data = JSON.parse(r.responseText);
			action(data)
		};
	};
	r.send(JSON.stringify(data));
	//r.send(data);
}

function docverwaltung() {
	action = function test(message) { byId("response").innerHTML = JSON.stringify(message)};
	send_form(byId("message").value, "/docverwaltung", action)
}

function resttest() {
	action = function test(message) { byId("response2").innerHTML = JSON.stringify(message)};
	send_form(byId("message2").value, byId("tgturi").value, action)
}
