function checkNoGlobalSecurity(spec) {
  const issues = [];
  if (!spec.security && !spec.securityDefinitions && !spec.components?.securitySchemes) {
    issues.push({
      rule_id: "SEC001",
      severity: "Critical",
      description: "No global security defined",
      location: "root",
      recommendation: "Define global security schemes (OAuth2, API Key, JWT)"
    });
  }
  return issues;
}

function checkUnprotectedEndpoints(spec) {
  const issues = [];
  const paths = spec.paths || {};
  for (const path in paths) {
    for (const method in paths[path]) {
      if (!paths[path][method].security) {
        issues.push({
          rule_id: "SEC002",
          severity: "High",
          description: "Unprotected endpoint",
          location: `paths.${path}.${method}`,
          recommendation: "Apply authentication"
        });
      }
    }
  }
  return issues;
}

function checkHttpAllowed(spec) {
  const issues = [];
  if (spec.servers) {
    spec.servers.forEach((s, i) => {
      if (s.url.startsWith("http://")) {
        issues.push({
          rule_id: "SEC003",
          severity: "High",
          description: "Insecure HTTP allowed",
          location: `servers[${i}].url`,
          recommendation: "Use HTTPS"
        });
      }
    });
  }
  return issues;
}

function checkRateLimitHeaders(spec) {
  const issues = [];
  const paths = spec.paths || {};
  for (const p in paths) {
    for (const m in paths[p]) {
      const responses = paths[p][m].responses || {};
      for (const r in responses) {
        const headers = responses[r].headers || {};
        if (!headers["X-RateLimit-Limit"]) {
          issues.push({
            rule_id: "SEC004",
            severity: "Medium",
            description: "No rate limit headers",
            location: `paths.${p}.${m}.responses.${r}`,
            recommendation: "Add X-RateLimit headers"
          });
        }
      }
    }
  }
  return issues;
}

function checkSensitiveQueryParams(spec) {
  const issues = [];
  const sensitive = ["password", "token", "secret", "api_key"];
  const paths = spec.paths || {};
  for (const p in paths) {
    for (const m in paths[p]) {
      const params = paths[p][m].parameters || [];
      params.forEach(param => {
        if (param.in === "query" && sensitive.includes(param.name)) {
          issues.push({
            rule_id: "SEC005",
            severity: "Medium",
            description: "Sensitive data in query parameter",
            location: `paths.${p}.${m}.parameters.${param.name}`,
            recommendation: "Move sensitive data to request body"
          });
        }
      });
    }
  }
  return issues;
}

function checkMissingErrorResponses(spec) {
  const issues = [];
  const paths = spec.paths || {};
  for (const p in paths) {
    for (const m in paths[p]) {
      const responses = paths[p][m].responses || {};
      if (!responses["401"] && !responses["403"] && !responses["429"]) {
        issues.push({
          rule_id: "SEC006",
          severity: "Medium",
          description: "Missing error responses",
          location: `paths.${p}.${m}.responses`,
          recommendation: "Define 401/403/429 responses"
        });
      }
    }
  }
  return issues;
}

function checkSecurityContact(spec) {
  const issues = [];
  if (!spec.info?.contact) {
    issues.push({
      rule_id: "SEC007",
      severity: "Low",
      description: "No security contact info",
      location: "info.contact",
      recommendation: "Add contact details"
    });
  }
  return issues;
}

function checkDeprecatedEndpoints(spec) {
  const issues = [];
  const paths = spec.paths || {};
  for (const p in paths) {
    for (const m in paths[p]) {
      if (paths[p][m].deprecated && !paths[p][m]["x-sunset-date"]) {
        issues.push({
          rule_id: "SEC008",
          severity: "Low",
          description: "Deprecated endpoint without sunset",
          location: `paths.${p}.${m}`,
          recommendation: "Add sunset date"
        });
      }
    }
  }
  return issues;
}

function checkWildcardServers(spec) {
  const issues = [];
  if (spec.servers) {
    spec.servers.forEach((s, i) => {
      if (s.url.includes("{") || s.url.includes("*")) {
        issues.push({
          rule_id: "SEC009",
          severity: "High",
          description: "Wildcard server URL",
          location: `servers[${i}].url`,
          recommendation: "Avoid wildcard hosts"
        });
      }
    });
  }
  return issues;
}

function checkInputValidation(spec) {
  const issues = [];
  const paths = spec.paths || {};
  for (const p in paths) {
    for (const m in paths[p]) {
      const params = paths[p][m].parameters || [];
      params.forEach(param => {
        const s = param.schema || {};
        if (!s.minLength && !s.maxLength && !s.pattern && !s.enum) {
          issues.push({
            rule_id: "SEC010",
            severity: "Medium",
            description: "No input validation",
            location: `paths.${p}.${m}.parameters.${param.name}`,
            recommendation: "Add validation constraints"
          });
        }
      });
    }
  }
  return issues;
}

module.exports = {
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
};