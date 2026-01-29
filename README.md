# Open-API-Static-Security-Analyzer
A static security analysis tool that finds common API security misconfigurations and offers remediation recommendations based on severity for Swagger and OpenAPI specifications.
A web-based static analysis tool called the OpenAPI Security Analyzer was created to find typical security flaws in Swagger and OpenAPI specifications. The tool assesses YAML or JSON-formatted API definitions and reports possible security flaws along with severity classification and remediation recommendations.
This project's goal is to help developers find API security flaws early on in the design and documentation stages, prior to deployment.

# Tech Stack Used :-
Frontend :- HTML, CSS, Vanilla JS , 
Backend :- Node.js, Express.js, js-yaml (Open API Parsing)

# How To Use 
1. Launch the backend server.
2. Launch a web browser and open frontend/index.html.
3. You can either paste the specification directly or upload an OpenAPI specification file.
4. Select "Analyze."
5. Examine the security score, summary, and specific findings.
6. Use filters to refine results based on rule ID or severity.

# Output :
The results of the analysis consist of:
1. Total number of problems found
2. Summary of severity
3. Total security rating
4. Comprehensive results table with
-Rule ID
-Level of Severity
-An explanation
-The specification's location
-Suggested correction

# Key Features : - 
- OpenAPI 2.0 (Swagger) and OpenAPI 3.x are supported.
- Accepts API specifications through:
- Upload a file (JSON or YAML)
- Input by direct paste
- Carries out static security analysis based on rules
- Sorts problems according to their severity:
- Critical High Medium
- Minimal
- Produces a total security score.
- Presents results in an organized, filterable table.
- Offers practical suggestions for every problem.
- A user-friendly and lightweight web interface

# Security Checks Implemented 
The following kinds of problems are currently detected by the analyzer:
- Absence of worldwide authentication systems
- Unprotected endpoints for APIs
- Configurations of insecure HTTP servers
- Sensitive information made public by query parameters
- Absence of rate-limiting headers
- Error response definitions (401, 403, and 429) are missing.
- Lack of security contact details
- Endpoints that have been deprecated but lack sunset information
- Templated or wildcard server URLs
- Absence of input validation restrictions
