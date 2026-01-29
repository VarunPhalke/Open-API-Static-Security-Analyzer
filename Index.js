const express = require("express");
const multer = require("multer");
const yaml = require("js-yaml");
const cors = require("cors");

const {
  checkNoGlobalSecurity,
  checkUnprotectedEndpoints,
  checkHttpAllowed,
  checkRateLimitHeaders,
  checkSensitiveQueryParams,
  checkMissingErrorResponses,
  checkSecurityContact,
  checkDeprecatedEndpoints,
  checkWildcardServers,
  checkInputValidation
} = require("./rules");

const app = express();
const upload = multer();

app.use(cors());
app.use(express.json());

function calculateScore(issues) {
  let score = 100;
  issues.forEach(issue => {
    if (issue.severity === "Critical") score -= 20;
    if (issue.severity === "High") score -= 10;
    if (issue.severity === "Medium") score -= 5;
    if (issue.severity === "Low") score -= 2;
  });
  return Math.max(score, 0);
}

function buildSummary(issues) {
  const summary = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  issues.forEach(issue => summary[issue.severity]++);
  return summary;
}

app.post("/analyze", upload.single("file"), (req, res) => {
  let specText;

  if (req.file) {
    specText = req.file.buffer.toString("utf-8");
  } else if (req.body.pasted_spec) {
    specText = req.body.pasted_spec;
  } else {
    return res.status(400).json({ error: "No OpenAPI spec provided" });
  }

  let spec;
  try {
    spec = yaml.load(specText);
  } catch (err) {
    return res.status(400).json({ error: "Invalid YAML or JSON" });
  }

  let issues = [];
  issues.push(...checkNoGlobalSecurity(spec));
  issues.push(...checkUnprotectedEndpoints(spec));
  issues.push(...checkHttpAllowed(spec));
  issues.push(...checkRateLimitHeaders(spec));
  issues.push(...checkSensitiveQueryParams(spec));
  issues.push(...checkMissingErrorResponses(spec));
  issues.push(...checkSecurityContact(spec));
  issues.push(...checkDeprecatedEndpoints(spec));
  issues.push(...checkWildcardServers(spec));
  issues.push(...checkInputValidation(spec));

  res.json({
    total_issues: issues.length,
    security_score: calculateScore(issues),
    summary: buildSummary(issues),
    issues
  });
});

app.listen(3000, () => {
  console.log("✅ Server running at http://localhost:3000");
});