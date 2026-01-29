# 🔐 Open API Static Security Analyzer

A web based static analysis tool that scans Swagger (OpenAPI) specifications to identify common API security misconfigurations and provide actionable remediation guidance.

This project was developed as part of an internship assignment to demonstrate secure API design practices, static analysis methodology, and professional full-stack implementation.

---

## 🚀 Features

- 📄 Accepts OpenAPI / Swagger specifications (YAML or JSON)
- 🛡️ Performs multiple static security checks
- 📊 Generates severity-based findings
- ⭐ Computes an overall security score
- 🔍 Allows filtering of results by severity and Rule ID
- 📋 Displays detailed recommendations for remediation
- 🖥️ Lightweight browser interface

---

## 🧠 Security Checks Implemented

The analyzer scans the OpenAPI spec and reports the following:

| Rule ID | Security Rule |
|---------|----------------|
| SEC001  | Missing global security definition |
| SEC002  | Unprotected endpoint |
| SEC003  | HTTP allowed (insecure scheme) |
| SEC004  | Missing rate limiting headers |
| SEC005  | Sensitive data in query parameter |
| SEC006  | Missing error responses |
| SEC007  | Missing security contact info |
| SEC008  | Deprecated endpoint without sunset |
| SEC009  | Wildcard server URL |
| SEC010  | No input validation constraints |

Each rule is classified by **severity** and includes **location** and **recommendation**.

---

## 🧪 Demo Workflow

1. Start the backend server
2. Open the frontend UI in a browser
3. Upload an OpenAPI file (JSON / YAML)
4. View:
   - Security summary (counts by severity)
   - Security score
   - Filterable detailed table
   - Actionable recommendations

---

## 🏗️ Tech Stack

**Backend**
- Node.js  
- Express.js  
- js-yaml  

**Frontend**
- HTML  
- CSS  
- Vanilla JavaScript

---

## 📁 Project Structure

