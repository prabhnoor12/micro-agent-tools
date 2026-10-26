/**
 * JWT Studio Pro — Cryptographic JWT Engine & JWKS Verifier
 * Powered by native Web Crypto API (SubtleCrypto).
 * Supports HS256, RS256, clock-skew inspection, token forging, and re-signing.
 */

const JwtEngine = (() => {

  function base64UrlDecode(str) {
    let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
    while (base64.length % 4) {
      base64 += '=';
    }
    const decodedBinary = atob(base64);
    const bytes = new Uint8Array(decodedBinary.length);
    for (let i = 0; i < decodedBinary.length; i++) {
      bytes[i] = decodedBinary.charCodeAt(i);
    }
    return new TextDecoder().decode(bytes);
  }

  function bufferToBase64Url(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function stringToBase64Url(str) {
    const encoder = new TextEncoder();
    return bufferToBase64Url(encoder.encode(str));
  }

  /**
   * Parse JWT string into components
   */
  function parseToken(jwtStr) {
    if (!jwtStr || typeof jwtStr !== 'string' || !jwtStr.trim()) {
      return { ok: false, error: 'Token string is empty' };
    }

    const parts = jwtStr.trim().split('.');
    if (parts.length !== 3) {
      return { ok: false, error: `Invalid JWT format: expected 3 dot-separated segments, got ${parts.length}` };
    }

    try {
      const rawHeader = base64UrlDecode(parts[0]);
      const rawPayload = base64UrlDecode(parts[1]);
      const header = JSON.parse(rawHeader);
      const payload = JSON.parse(rawPayload);

      return {
        ok: true,
        header,
        payload,
        rawHeader,
        rawPayload,
        rawSignature: parts[2],
        signedData: `${parts[0]}.${parts[1]}`
      };
    } catch (err) {
      return { ok: false, error: 'Malformed Base64URL or JSON: ' + err.message };
    }
  }

  /**
   * Evaluate Token Expiration & Clock Skew
   */
  function evaluateExpiration(payload, clockSkewSeconds = 0) {
    const now = Math.floor(Date.now() / 1000);
    const exp = payload.exp ? Number(payload.exp) : null;
    const nbf = payload.nbf ? Number(payload.nbf) : null;
    const iat = payload.iat ? Number(payload.iat) : null;

    let isExpired = false;
    let isNotYetValid = false;
    let expMessage = "";
    let status = "ACTIVE";

    if (exp !== null) {
      const diff = exp - now;
      if (diff + clockSkewSeconds < 0) {
        isExpired = true;
        status = "EXPIRED";
        const expiredMinutes = Math.abs(Math.round(diff / 60));
        expMessage = `Token expired ${expiredMinutes} minutes ago (${new Date(exp * 1000).toLocaleString()})`;
      } else {
        const remainingMinutes = Math.round(diff / 60);
        expMessage = `Token active. Expires in ${remainingMinutes} minutes (${new Date(exp * 1000).toLocaleString()})`;
      }
    } else {
      expMessage = "No 'exp' claim found (Never expires)";
    }

    if (nbf !== null && (nbf - clockSkewSeconds) > now) {
      isNotYetValid = true;
      status = "NOT_BEFORE_FUTURE";
      expMessage = `Token not valid before ${new Date(nbf * 1000).toLocaleString()}`;
    }

    return {
      status,
      isExpired,
      isNotYetValid,
      expMessage,
      now,
      expDate: exp ? new Date(exp * 1000).toISOString() : null,
      iatDate: iat ? new Date(iat * 1000).toISOString() : null
    };
  }

  /**
   * Verify HS256 Token Signature
   */
  async function verifyHs256Signature(signedData, receivedSignatureB64Url, secretKeyStr) {
    const cryptoSubtle = (typeof window !== 'undefined' ? window.crypto : globalThis.crypto).subtle;
    const encoder = new TextEncoder();
    const secretKey = encoder.encode(secretKeyStr);

    const key = await cryptoSubtle.importKey(
      'raw',
      secretKey,
      { name: 'HMAC', hash: { name: 'SHA-256' } },
      false,
      ['sign']
    );

    const sigBuffer = await cryptoSubtle.sign(
      'HMAC',
      key,
      encoder.encode(signedData)
    );

    const expectedSigB64Url = bufferToBase64Url(sigBuffer);
    const isValid = expectedSigB64Url === receivedSignatureB64Url;

    return {
      isValid,
      expectedSignature: expectedSigB64Url,
      receivedSignature: receivedSignatureB64Url
    };
  }

  /**
   * Re-sign / Forge JWT Token (HS256)
   */
  async function forgeHs256Token(headerObj, payloadObj, secretKeyStr) {
    const cryptoSubtle = (typeof window !== 'undefined' ? window.crypto : globalThis.crypto).subtle;
    const encoder = new TextEncoder();

    const headB64 = stringToBase64Url(JSON.stringify(headerObj));
    const payB64 = stringToBase64Url(JSON.stringify(payloadObj));
    const signedData = `${headB64}.${payB64}`;

    const key = await cryptoSubtle.importKey(
      'raw',
      encoder.encode(secretKeyStr),
      { name: 'HMAC', hash: { name: 'SHA-256' } },
      false,
      ['sign']
    );

    const sigBuffer = await cryptoSubtle.sign(
      'HMAC',
      key,
      encoder.encode(signedData)
    );

    const sigB64 = bufferToBase64Url(sigBuffer);
    return `${signedData}.${sigB64}`;
  }

  /**
   * Generate Integration Code Snippets
   */
  function generateNodeVerifyCode(secret) {
    return `// Node.js (jsonwebtoken)
const jwt = require('jsonwebtoken');

try {
  const decoded = jwt.verify(token, '${secret}', {
    algorithms: ['HS256'],
    clockTolerance: 10 // 10 seconds leeway
  });
  console.log('Decoded claims:', decoded);
} catch (err) {
  console.error('JWT verification failed:', err.message);
}`;
  }

  function generatePythonVerifyCode(secret) {
    return `# Python (PyJWT)
import jwt

try:
    decoded = jwt.decode(token, '${secret}', algorithms=['HS256'], leeway=10)
    print("Decoded claims:", decoded)
except jwt.ExpiredSignatureError:
    print("Token has expired")
except jwt.InvalidTokenError as e:
    print("Invalid token:", str(e))`;
  }

  // Top 50 Common JWT Secrets Dictionary for Audit Scanner
  const TOP_50_JWT_SECRETS = [
    'secret', 'jwtsecret', '123456', 'password', 'supersecret', 'admin', 'test',
    'secret123', 'keyboard cat', 'mysecret', 'development', 'token_secret',
    'changeme', 'auth0_secret', 'jwt_secret', 'node_secret', 'express_secret',
    '12345678', 'qwerty', '123456789', 'letmein', 'default', 'root', 'master',
    'app_secret', 'api_secret', 'shhhhh', 'private_key', 'passphrase', 'secure',
    'demo', 'staging', 'production', 'dev_secret', 'testing', 'hello', 'login',
    'auth_key', 'guest', 'user', 'access_token', 'temp', 'foobar', 'barbaz',
    'whsec_test', 'sample', 'test1234', 'developer', 'welcome', 'system'
  ];

  /**
   * Fast Brute-Force Dictionary Scanner for Weak HMAC-SHA256 Secrets
   */
  async function crackWeakSecret(signedData, receivedSignatureB64Url) {
    for (const secretCandidate of TOP_50_JWT_SECRETS) {
      const res = await verifyHs256Signature(signedData, receivedSignatureB64Url, secretCandidate);
      if (res.isValid) {
        return { cracked: true, secret: secretCandidate };
      }
    }
    return { cracked: false };
  }

  /**
   * Remote JWKS Endpoint Verifier (Auth0, Clerk, Firebase, Supabase)
   */
  async function verifyJwksEndpoint(jwksUrl, tokenHeader) {
    try {
      const resp = await fetch(jwksUrl);
      if (!resp.ok) throw new Error(`HTTP ${resp.status} ${resp.statusText}`);
      const jwks = await resp.json();
      if (!jwks.keys || !Array.isArray(jwks.keys)) {
        throw new Error('Invalid JWKS structure: response does not contain a "keys" array');
      }

      const kid = tokenHeader ? tokenHeader.kid : null;
      let matchedKey = null;
      if (kid) {
        matchedKey = jwks.keys.find(k => k.kid === kid);
      } else if (jwks.keys.length > 0) {
        matchedKey = jwks.keys[0];
      }

      if (!matchedKey) {
        return {
          ok: false,
          error: `No matching key with kid='${kid || '(unspecified)'}' found in JWKS (found ${jwks.keys.length} keys)`
        };
      }

      return {
        ok: true,
        matchedKey,
        kid: matchedKey.kid,
        kty: matchedKey.kty,
        alg: matchedKey.alg || (tokenHeader ? tokenHeader.alg : 'RS256'),
        keysCount: jwks.keys.length
      };
    } catch (err) {
      return { ok: false, error: err.message };
    }
  }

  const engine = {
    parseToken,
    evaluateExpiration,
    verifyHs256Signature,
    forgeHs256Token,
    generateNodeVerifyCode,
    generatePythonVerifyCode,
    crackWeakSecret,
    verifyJwksEndpoint,
    TOP_50_JWT_SECRETS
  };

  if (typeof window !== 'undefined') {
    window.JwtEngine = engine;
  }
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = engine;
  }

  return engine;

})();
