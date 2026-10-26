/**
 * EnvMatrix — Cross-Environment Matrix Builder & Security Sentinel
 * Detects:
 * - Missing keys in Production (2 AM crash prevention)
 * - Test keys in Production (sk_test_...)
 * - Live keys in Development (sk_live_...)
 * - Default weak secrets (password, 123456, changeme)
 * - Port & URI format violations
 */

const EnvValidator = (() => {

  const WEAK_SECRETS = new Set([
    'password', 'password123', 'admin', 'secret', 'changeme', 'change_me',
    'your_api_key_here', 'todo', 'test', '123456', '12345678', 'root',
    'default', 'null', 'undefined'
  ]);

  /**
   * Validate a single key-value entry for type/formatting
   */
  function validateValueType(key, val) {
    if (val === undefined || val === null || val === '') return null;
    const lowerKey = key.toLowerCase();
    const cleanVal = val.trim();

    // 1. Port Validation
    if (lowerKey === 'port' || lowerKey.endsWith('_port')) {
      const portNum = Number(cleanVal);
      if (!Number.isInteger(portNum) || portNum < 1 || portNum > 65535) {
        return {
          type: 'INVALID_PORT',
          severity: 'WARNING',
          message: `Expected valid port integer (1-65535), got '${cleanVal}'`
        };
      }
    }

    // 2. Database & Connection URI Validation
    if (lowerKey.endsWith('_url') || lowerKey.endsWith('_uri') || lowerKey === 'database_url' || lowerKey === 'redis_url') {
      const validUriPattern = /^(https?|postgres|postgresql|mysql|mongodb(\+srv)?|redis|amqp):\/\/.+/i;
      if (!validUriPattern.test(cleanVal) && !cleanVal.includes('${')) {
        return {
          type: 'INVALID_URI',
          severity: 'WARNING',
          message: `Connection string appears malformed or missing standard URI scheme`
        };
      }
    }

    // 3. Boolean Flag Validation
    if (lowerKey.startsWith('enable_') || lowerKey.startsWith('is_') || lowerKey.endsWith('_enabled')) {
      const boolPattern = /^(true|false|1|0|yes|no)$/i;
      if (!boolPattern.test(cleanVal)) {
        return {
          type: 'INVALID_BOOLEAN',
          severity: 'INFO',
          message: `Flag expected to be boolean (true/false/1/0), got '${cleanVal}'`
        };
      }
    }

    return null;
  }

  /**
   * Scan for security leaks & danger patterns
   */
  function auditKeySecurity(key, val, envName) {
    if (val === undefined || val === null || val === '') return null;
    const cleanVal = val.trim();
    const lowerVal = cleanVal.toLowerCase();

    // 1. Test Key Leaked in Production
    if (envName === 'prod' || envName === 'production') {
      if (lowerVal.startsWith('sk_test_') || lowerVal.startsWith('pk_test_') || lowerVal.startsWith('whsec_test_') || lowerVal.includes('sandbox')) {
        return {
          type: 'TEST_KEY_IN_PROD',
          severity: 'CRITICAL',
          message: `Test/Sandbox API key detected in Production! Live transactions or webhooks will fail.`
        };
      }
    }

    // 2. Live Key Leaked in Development
    if (envName === 'dev' || envName === 'development') {
      if (lowerVal.startsWith('sk_live_') || lowerVal.startsWith('pk_live_') || lowerVal.includes('live_secret')) {
        return {
          type: 'LIVE_KEY_IN_DEV',
          severity: 'CRITICAL',
          message: `Production LIVE key detected in Development environment! Testing could charge real customer cards or corrupt live databases.`
        };
      }
    }

    // 3. Weak Default Secret
    if (WEAK_SECRETS.has(lowerVal)) {
      return {
        type: 'WEAK_SECRET',
        severity: envName === 'prod' ? 'CRITICAL' : 'WARNING',
        message: `Value matches weak default placeholder '${cleanVal}'. Must be rotated before public release.`
      };
    }

    // 4. Exposed RSA / Private Key
    if (cleanVal.includes('BEGIN PRIVATE KEY') || cleanVal.includes('BEGIN RSA PRIVATE KEY')) {
      return {
        type: 'PRIVATE_KEY_EXPOSED',
        severity: 'WARNING',
        message: `Raw Private Key embedded directly in .env. Consider using secret manager or Base64 encoding.`
      };
    }

    return null;
  }

  /**
   * Build 3-Way Cross-Environment Matrix
   * @param {Map} devMap
   * @param {Map} stagingMap
   * @param {Map} prodMap
   */
  function buildMatrix(devMap, stagingMap, prodMap) {
    const allKeys = Array.from(new Set([
      ...devMap.keys(),
      ...stagingMap.keys(),
      ...prodMap.keys()
    ])).sort();

    const matrixRows = [];
    const auditReport = [];
    const stats = {
      totalKeys: allKeys.length,
      missingInProd: 0,
      missingInStaging: 0,
      testKeyInProd: 0,
      liveKeyInDev: 0,
      complete: 0
    };

    allKeys.forEach(key => {
      const devVal = devMap.get(key);
      const stagingVal = stagingMap.get(key);
      const prodVal = prodMap.get(key);

      const hasDev = devVal !== undefined;
      const hasStaging = stagingVal !== undefined;
      const hasProd = prodVal !== undefined;

      let status = 'COMPLETE';
      const rowIssues = [];

      // Check Missing Keys
      if (!hasProd && (hasDev || hasStaging)) {
        status = 'MISSING_IN_PROD';
        stats.missingInProd++;
        const issue = {
          key,
          env: 'production',
          severity: 'CRITICAL',
          type: 'MISSING_IN_PROD',
          message: `Variable '${key}' exists in ${hasStaging ? 'Staging' : 'Development'} but is MISSING in Production. This will cause silent 2 AM runtime crashes.`
        };
        rowIssues.push(issue);
        auditReport.push(issue);
      } else if (!hasStaging && (hasDev || hasProd)) {
        status = 'MISSING_IN_STAGING';
        stats.missingInStaging++;
        const issue = {
          key,
          env: 'staging',
          severity: 'WARNING',
          type: 'MISSING_IN_STAGING',
          message: `Variable '${key}' is missing in Staging environment.`
        };
        rowIssues.push(issue);
        auditReport.push(issue);
      } else if (hasDev && !hasStaging && !hasProd) {
        status = 'DEV_ONLY';
      } else {
        stats.complete++;
      }

      // Security & Leak Checks for each environment
      const envChecks = [
        { name: 'dev', val: devVal },
        { name: 'staging', val: stagingVal },
        { name: 'prod', val: prodVal }
      ];

      envChecks.forEach(e => {
        if (e.val !== undefined) {
          const leakIssue = auditKeySecurity(key, e.val, e.name);
          if (leakIssue) {
            if (leakIssue.type === 'TEST_KEY_IN_PROD') stats.testKeyInProd++;
            if (leakIssue.type === 'LIVE_KEY_IN_DEV') stats.liveKeyInDev++;
            const fullIssue = { key, env: e.name, ...leakIssue };
            rowIssues.push(fullIssue);
            auditReport.push(fullIssue);
          }

          const typeIssue = validateValueType(key, e.val);
          if (typeIssue) {
            const fullTypeIssue = { key, env: e.name, ...typeIssue };
            rowIssues.push(fullTypeIssue);
            auditReport.push(fullTypeIssue);
          }
        }
      });

      matrixRows.push({
        key,
        status,
        dev: { exists: hasDev, value: devVal },
        staging: { exists: hasStaging, value: stagingVal },
        prod: { exists: hasProd, value: prodVal },
        issues: rowIssues
      });
    });

    return {
      matrixRows,
      auditReport,
      stats
    };
  }

  const validator = {
    validateValueType,
    auditKeySecurity,
    buildMatrix
  };

  if (typeof window !== 'undefined') {
    window.EnvValidator = validator;
  }
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = validator;
  }

  return validator;

})();
