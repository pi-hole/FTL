/* Pi-hole: A black hole for Internet advertisements
 *  (c) 2021 Pi-hole, LLC (https://pi-hole.net)
 *  Network-wide ad blocking via your own hardware.
 *
 *  This file is copyright under the latest version of the EUPL.
 *  Please see LICENSE file for your rights under this license. */

// GET implementation
async function getData(url = '') {
	const docEl = document.getElementById('thedoc');
	const sid = docEl.attributes["api-key-value"].value;
	const response = await fetch(url, {
		method: 'GET',
		headers: {'Content-Type': 'application/json', 'X-FTL-SID': sid}
	});
	return response.json();
}

// DELETE implementation
async function deleteData(url = '') {
	const docEl = document.getElementById('thedoc');
	const sid = docEl.attributes["api-key-value"].value;
	const response = await fetch(url, {
		method: 'DELETE',
		headers: {'X-FTL-SID': sid}
	});
	return response;
}

// POST implementation
async function postData(url = '', data = {}) {
	const docEl = document.getElementById('thedoc');
	const sid = docEl.attributes["api-key-value"].value;
	const response = await fetch(url, {
		method: 'POST',
		headers: {'Content-Type': 'application/json', 'X-FTL-SID': sid},
		body: JSON.stringify(data)
	});
	return response.json();
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
	docEl.setAttribute('api-key-value', "-");
	const btn = document.getElementById('loginbtn');
	btn.classList.remove('green');
	btn.classList.remove('red');
	btn.textContent = 'Login';
}

// Login using password
function loginout(){
	const docEl = document.getElementById('thedoc');
	if(docEl.attributes["api-key-value"].value === '-') {
		var pw = document.getElementById('loginpw').value;
		postData('/api/auth', {password: pw})
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
document.addEventListener('DOMContentLoaded', (event) => {
	let docEl = document.getElementById("thedoc");

	docEl.addEventListener('after-try', (e) => {
		console.log(e.detail.response);
		if(e.detail.response.status === 401) {
			loginFAIL();
		}
	});
});
