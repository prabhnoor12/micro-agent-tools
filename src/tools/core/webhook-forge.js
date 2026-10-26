/**
 * WebhookForge — Cryptographic HMAC Engine & Signature Diagnostic Analyzer
 * Powered by native Web Crypto API (SubtleCrypto).
 * 100% Client-side. Secrets never leave the browser.
 */

const HmacEngine = (() => {

  const PROVIDERS = {
    stripe: {
      name: "Stripe",
      headerName: "Stripe-Signature",
      algo: "SHA-256",
      secretPrefix: "whsec_",
      docUrl: "https://stripe.com/docs/webhooks/signatures"
    },
    github: {
      name: "GitHub",
      headerName: "X-Hub-Signature-256",
      algo: "SHA-256",
      secretPrefix: "",
      docUrl: "https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries"
    },
    shopify: {
      name: "Shopify",
      headerName: "X-Shopify-Hmac-Sha256",
      algo: "SHA-256",
      secretPrefix: "shpss_",
      docUrl: "https://shopify.dev/docs/apps/build/webhooks/subscribe/https#verifying-webhooks"
    },
    slack: {
      name: "Slack",
      headerName: "X-Slack-Signature",
      algo: "SHA-256",
      secretPrefix: "",
      docUrl: "https://api.slack.com/authentication/verifying-requests-from-slack"
    },
    svix: {
      name: "Svix (Standard Webhooks)",
      headerName: "svix-signature",
      algo: "SHA-256",
      secretPrefix: "whsec_",
      docUrl: "https://docs.svix.com/receiving/verifying-payloads/how"
    },
    paddle: {
      name: "Paddle",
      headerName: "Paddle-Signature",
      algo: "SHA-256",
      secretPrefix: "pdl_ntf_set_",
      docUrl: "https://developer.paddle.com/webhooks/overview#verifying-signatures"
    },
    generic: {
      name: "Generic HMAC-SHA256",
      headerName: "X-Signature",
      algo: "SHA-256",
      secretPrefix: "",
      docUrl: ""
    }
  };

  // Convert ArrayBuffer to Hex String
  function bufferToHex(buffer) {
    return Array.from(new Uint8Array(buffer))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  // Convert ArrayBuffer to Base64 String
  function bufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  // Decode Base64 to Uint8Array
  function base64ToUint8Array(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  // Timing-safe string comparison
  function timingSafeEqual(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string') return false;
    if (a.length !== b.length) return false;
    let mismatch = 0;
    for (let i = 0; i < a.length; i++) {
      mismatch |= (a.charCodeAt(i) ^ b.charCodeAt(i));
    }
    return mismatch === 0;
  }

  // Weak Secret Dictionary Sentinel Check
  const WEAK_SECRETS_LIST = [
    'secret', 'webhook_secret', 'whsec_test', '123456', '12345678', 'password',
    'test', 'stripe_test', 'dev_secret', 'admin', 'changeme', 'my_secret',
    'sample_secret', 'qwerty', 'temp', 'default', 'api_secret'
  ];

  function checkWeakSecret(secret) {
    if (!secret || typeof secret !== 'string') return { isWeak: true, reason: 'Empty secret provided' };
    const trimmed = secret.trim().toLowerCase();
    if (trimmed.length < 8) {
      return { isWeak: true, reason: 'Secret is under 8 characters (vulnerable to brute-force attacks)' };
    }
    for (const weak of WEAK_SECRETS_LIST) {
      if (trimmed === weak || trimmed === 'whsec_' + weak || trimmed === 'shpss_' + weak) {
        return { isWeak: true, reason: `Matches well-known dictionary or test placeholder ('${weak}')` };
      }
    }
    return { isWeak: false };
  }


  /**
   * Native Web Crypto HMAC Calculation
   */
  async function computeRawHmac(algo, secretKeyBytes, dataBytes) {
    const cryptoSubtle = (typeof window !== 'undefined' ? window.crypto : globalThis.crypto).subtle;
    const cryptoKey = await cryptoSubtle.importKey(
      'raw',
      secretKeyBytes,
      { name: 'HMAC', hash: { name: algo } },
      false,
      ['sign']
    );

    const signatureBuffer = await cryptoSubtle.sign(
      'HMAC',
      cryptoKey,
      dataBytes
    );

    return signatureBuffer;
  }

  /**
   * Build Provider Signed String & Expected Signature
   */
  async function generateProviderSignature(providerKey, payload, secret, options = {}) {
    const encoder = new TextEncoder();
    const timestamp = options.timestamp !== undefined ? options.timestamp : Math.floor(Date.now() / 1000);
    const msgId = options.msgId || `msg_${Math.random().toString(36).substring(2, 10)}`;

    let signedString = "";
    let signatureValue = "";
    let headerName = PROVIDERS[providerKey]?.headerName || "X-Signature";
    let fullHeader = "";

    // Normalize raw payload string
    const rawPayload = typeof payload === 'string' ? payload : JSON.stringify(payload);

    switch (providerKey) {
      case 'stripe': {
        signedString = `${timestamp}.${rawPayload}`;
        const secretBytes = encoder.encode(secret.trim());
        const dataBytes = encoder.encode(signedString);
        const sigBuffer = await computeRawHmac('SHA-256', secretBytes, dataBytes);
        const hexSig = bufferToHex(sigBuffer);
        signatureValue = hexSig;
        fullHeader = `t=${timestamp},v1=${hexSig}`;
        break;
      }

      case 'github': {
        signedString = rawPayload;
        const secretBytes = encoder.encode(secret.trim());
        const dataBytes = encoder.encode(signedString);
        const sigBuffer = await computeRawHmac('SHA-256', secretBytes, dataBytes);
        const hexSig = bufferToHex(sigBuffer);
        signatureValue = hexSig;
        fullHeader = `sha256=${hexSig}`;
        break;
      }

      case 'shopify': {
        signedString = rawPayload;
        const secretBytes = encoder.encode(secret.trim());
        const dataBytes = encoder.encode(signedString);
        const sigBuffer = await computeRawHmac('SHA-256', secretBytes, dataBytes);
        const b64Sig = bufferToBase64(sigBuffer);
        signatureValue = b64Sig;
        fullHeader = b64Sig;
        break;
      }

      case 'slack': {
        signedString = `v0:${timestamp}:${rawPayload}`;
        const secretBytes = encoder.encode(secret.trim());
        const dataBytes = encoder.encode(signedString);
        const sigBuffer = await computeRawHmac('SHA-256', secretBytes, dataBytes);
        const hexSig = bufferToHex(sigBuffer);
        signatureValue = hexSig;
        fullHeader = `v0=${hexSig}`;
        break;
      }

      case 'svix': {
        signedString = `${msgId}.${timestamp}.${rawPayload}`;
        // Svix secret key format is often whsec_base64
        let secretBytes;
        let cleanSecret = secret.trim();
        if (cleanSecret.startsWith('whsec_')) cleanSecret = cleanSecret.substring(6);
        try {
          secretBytes = base64ToUint8Array(cleanSecret);
        } catch (e) {
          secretBytes = encoder.encode(secret.trim());
        }
        const dataBytes = encoder.encode(signedString);
        const sigBuffer = await computeRawHmac('SHA-256', secretBytes, dataBytes);
        const b64Sig = bufferToBase64(sigBuffer);
        signatureValue = b64Sig;
        fullHeader = `v1,${b64Sig}`;
        break;
      }

      case 'paddle': {
        signedString = `${timestamp}:${rawPayload}`;
        const secretBytes = encoder.encode(secret.trim());
        const dataBytes = encoder.encode(signedString);
        const sigBuffer = await computeRawHmac('SHA-256', secretBytes, dataBytes);
        const hexSig = bufferToHex(sigBuffer);
        signatureValue = hexSig;
        fullHeader = `ts=${timestamp};h1=${hexSig}`;
        break;
      }

      case 'generic':
      default: {
        signedString = rawPayload;
        const secretBytes = encoder.encode(secret.trim());
        const dataBytes = encoder.encode(signedString);
        const sigBuffer = await computeRawHmac(options.algo || 'SHA-256', secretBytes, dataBytes);
        const hexSig = bufferToHex(sigBuffer);
        signatureValue = hexSig;
        fullHeader = hexSig;
        break;
      }
    }

    return {
      providerKey,
      headerName,
      fullHeader,
      signatureValue,
      signedString,
      timestamp,
      msgId
    };
  }

  /**
   * Diagnostic Signature Verification
   * Parses received headers, re-computes expected signature, and detects common pitfalls
   */
  async function verifySignature(providerKey, payload, secret, receivedHeader) {
    const diagnostics = [];
    const now = Math.floor(Date.now() / 1000);

    if (!payload || !payload.trim()) {
      diagnostics.push({ level: 'error', text: 'Payload is empty. Verification cannot run.' });
      return { isValid: false, diagnostics };
    }
    if (!secret || !secret.trim()) {
      diagnostics.push({ level: 'error', text: 'Signing secret is missing.' });
      return { isValid: false, diagnostics };
    }
    if (!receivedHeader || !receivedHeader.trim()) {
      diagnostics.push({ level: 'error', text: 'Received signature header is missing or empty.' });
      return { isValid: false, diagnostics };
    }

    // Secret prefix checks
    const providerMeta = PROVIDERS[providerKey];
    if (providerMeta && providerMeta.secretPrefix && !secret.trim().startsWith(providerMeta.secretPrefix)) {
      diagnostics.push({
        level: 'warning',
        text: `Secret does not start with standard '${providerMeta.secretPrefix}' prefix. Make sure you copied the Webhook signing secret, not the API key.`
      });
    }

    // Extract timestamp and signature components based on provider
    let extractedTimestamp = now;
    let extractedSignature = receivedHeader.trim();
    let msgId = `msg_test`;

    if (providerKey === 'stripe') {
      const parts = receivedHeader.split(',');
      const tPart = parts.find(p => p.trim().startsWith('t='));
      const v1Part = parts.find(p => p.trim().startsWith('v1='));

      if (!tPart || !v1Part) {
        diagnostics.push({
          level: 'error',
          text: "Malformed Stripe-Signature header. Expected format: 't=1614555000,v1=abcdef...'"
        });
      } else {
        extractedTimestamp = parseInt(tPart.split('=')[1], 10);
        extractedSignature = v1Part.split('=')[1];

        // Timestamp tolerance check (Stripe default: 300 seconds / 5 mins)
        const ageSeconds = now - extractedTimestamp;
        if (Math.abs(ageSeconds) > 300) {
          diagnostics.push({
            level: 'warning',
            text: `Timestamp drift detected: Payload is ${Math.round(ageSeconds / 60)} minutes old (${ageSeconds}s). Official Stripe SDK will throw a SignatureVerificationError due to clock skew.`
          });
        } else {
          diagnostics.push({
            level: 'info',
            text: `Timestamp is fresh (${ageSeconds}s difference, well within the 300s tolerance window).`
          });
        }
      }
    } else if (providerKey === 'github') {
      if (receivedHeader.startsWith('sha256=')) {
        extractedSignature = receivedHeader.substring(7);
      } else if (receivedHeader.startsWith('sha1=')) {
        diagnostics.push({
          level: 'warning',
          text: "Header uses legacy SHA-1 ('X-Hub-Signature'). GitHub recommends SHA-256 ('X-Hub-Signature-256')."
        });
        extractedSignature = receivedHeader.substring(5);
      }
    } else if (providerKey === 'slack') {
      if (receivedHeader.startsWith('v0=')) {
        extractedSignature = receivedHeader.substring(3);
      }
    } else if (providerKey === 'svix') {
      const parts = receivedHeader.split(',');
      if (parts.length > 1 && parts[0].trim() === 'v1') {
        extractedSignature = parts[1].trim();
      }
    } else if (providerKey === 'paddle') {
      const parts = receivedHeader.split(';');
      const tsPart = parts.find(p => p.trim().startsWith('ts='));
      const h1Part = parts.find(p => p.trim().startsWith('h1='));
      if (tsPart && h1Part) {
        extractedTimestamp = parseInt(tsPart.split('=')[1], 10);
        extractedSignature = h1Part.split('=')[1];
      }
    }

    // Compute expected signature
    const computed = await generateProviderSignature(providerKey, payload, secret, {
      timestamp: extractedTimestamp,
      msgId
    });

    const isMatch = timingSafeEqual(computed.signatureValue.toLowerCase(), extractedSignature.toLowerCase());

    if (isMatch) {
      diagnostics.push({
        level: 'success',
        text: 'Cryptographic signature is 100% VALID! Timing-safe HMAC match confirmed.'
      });
    } else {
      diagnostics.push({
        level: 'error',
        text: 'Signature mismatch! The payload or secret does not match what generated the received header.'
      });

      // Whitespace / formatting check
      try {
        const parsed = JSON.parse(payload);
        const reStringified = JSON.stringify(parsed);
        if (payload !== reStringified) {
          diagnostics.push({
            level: 'warning',
            text: "Potential Whitespace Mutation: The raw payload text has formatting/spacing that differs from minified JSON. Remember webhooks must be verified against the EXACT raw unparsed HTTP body string."
          });
        }
      } catch (e) {
        // Not valid JSON, which might be intentional
      }

      if (secret.startsWith(' ') || secret.endsWith(' ')) {
        diagnostics.push({
          level: 'warning',
          text: "Trailing or leading whitespace found in your secret key string."
        });
      }

      const weakCheck = checkWeakSecret(secret);
      if (weakCheck.isWeak) {
        diagnostics.push({
          level: 'warning',
          text: `Insecure Secret Warning: ${weakCheck.reason}. Use a 32+ byte cryptographically random secret in production.`
        });
      }
    }

    return {
      isValid: isMatch,
      expectedSignature: computed.signatureValue,
      receivedSignature: extractedSignature,
      fullExpectedHeader: computed.fullHeader,
      signedString: computed.signedString,
      timestamp: extractedTimestamp,
      diagnostics
    };
  }

  const engine = {
    PROVIDERS,
    computeRawHmac,
    generateProviderSignature,
    verifySignature,
    timingSafeEqual,
    checkWeakSecret
  };

  if (typeof window !== 'undefined') {
    window.HmacEngine = engine;
  }
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = engine;
  }

  return engine;

})();
