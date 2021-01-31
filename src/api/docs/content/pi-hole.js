/* Pi-hole: A black hole for Internet advertisements
 *  (c) 2021 Pi-hole, LLC (https://pi-hole.net)
 *  Network-wide ad blocking via your own hardware.
 *
 *  This file is copyright under the latest version of the EUPL.
 *  Please see LICENSE file for your rights under this license. */

function computeResponse(password, challenge) {
	// Compute password hash twice to mitigate rainbow
	// table vulnerability
	console.log(password, challenge);
	return sha256(challenge + ":" + sha256(sha256(password)));
}

// GET implementation
async function getData(url = '') {
	const response = await fetch(url, {
		method: 'GET',
		headers: {'Content-Type': 'application/json'}
	});
	return response.json();
}

// DELETE implementation
async function deleteData(url = '') {
	const response = await fetch(url, {
		method: 'DELETE'
	});
	return response;
}

// POST implementation
async function postData(url = '', data = {}) {
	const response = await fetch(url, {
		method: 'POST',
		headers: {'Content-Type': 'application/json'},
		body: JSON.stringify(data)
	});
	return response.json();
}

// Send response
function login2(response) {
	postData('/api/auth', {response: response})
	.then(data => {
		if(data.session.valid === true) {
			loginOk(data.session.sid);
		} else {
			loginFAIL();
		}
	})
	.catch((error) => {
		loginFAIL();
		console.error('Error:', error);
	});
}

// Mark login as OK
function loginOk(sid) {
	const docEl = document.getElementById('thedoc');
	docEl.setAttribute('api-key-value', sid);
	const btn = document.getElementById('loginbtn');
	btn.classList.add('green');
	btn.classList.remove('red');
	btn.textContent = 'Logout';
}

// Mark login as FAIL
function loginFAIL() {
	const docEl = document.getElementById('thedoc');
	docEl.setAttribute('api-key-value', '-');
	const btn = document.getElementById('loginbtn');
	btn.classList.remove('green');
	btn.classList.add('red');
	btn.textContent = 'Login';
}

// Mark logout as OK
function logoutOk() {
	const docEl = document.getElementById('thedoc');
	docEl.setAttribute('api-key-value', '-');
	const btn = document.getElementById('loginbtn');
	btn.classList.remove('green');
	btn.classList.remove('red');
	btn.textContent = 'Login';
}
function login1(pw)
{
	getData('/api/auth')
	.then(data => {
		if("challenge" in data && data.challenge !== null) {
			var response = computeResponse(pw, data.challenge);
			login2(response);
		} else if(data.session.valid === true) {
			loginOk(data.session.sid);
		} else {
			loginFAIL();
		}
	})
	.catch((error) => {
		loginFAIL();
		console.error('Error:', error);
	});
}

// Start login sequence by getting challenge
function login(){
	const docEl = document.getElementById('thedoc');
	if(docEl.attributes["api-key-value"].value === '-') {
		var pw = document.getElementById('loginpw').value;
		login1(pw);
	} else {
		deleteData('/api/auth')
		.then(logoutOk())
		.catch((error) => {
			loginFAIL();
			console.error('Error:', error);
		});
	}
}

function setStyle(style) {
	const docEl = document.getElementById('thedoc');
	docEl.setAttribute('render-style', style);
	docEl.setAttribute('allow-search', style !== 'view');
}