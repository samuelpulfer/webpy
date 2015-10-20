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
	
	$.ajax({
		url: '/json1',
		type: 'POST',
		contentType: "application/x-www-form-urlencoded; charset=utf-8",
		dataType: 'json',
		
		data: params,
		
		error: function(xhr, str, str) {
			document.getElementById('info').innerHTML = 'Communication error: '+xhr.status+' '+str;
		},
		
		success: function(data) {
			document.getElementById('info').innerHTML = 'Success';
			//console.log(data)
			
			document.getElementById("result").innerHTML = 
				data.i1 + " <em>and</em> " + data.i2 + " <em>equals</em> " + data.res;
		}
		
	});
}
