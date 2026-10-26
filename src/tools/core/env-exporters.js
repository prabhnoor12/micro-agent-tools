/**
 * EnvMatrix — 1-Click Multi-Format Exporters
 * Converts .env into Docker Compose, Kubernetes Secret, GitHub Actions CLI, Terraform, and .env.example
 */

const EnvExporters = (() => {

  /**
   * Generate sanitized .env.example
   * Keeps keys and comments, strips all actual secret values
   */
  function toExample(entries) {
    if (!entries || !entries.length) return "";
    return entries.map(e => {
      if (e.type === 'empty') return "";
      if (e.type === 'comment') return `# ${e.comment}`;
      if (e.type === 'variable') {
        const lower = e.key.toLowerCase();
        let placeholder = "";
        if (lower.includes('port')) placeholder = "3000";
        else if (lower.includes('url') || lower.includes('uri')) placeholder = "https://example.com";
        else if (lower.includes('secret') || lower.includes('key') || lower.includes('token')) placeholder = "your_secret_here";
        else if (lower.includes('env')) placeholder = "production";

        let line = `${e.key}=${placeholder}`;
        if (e.inlineComment) line += ` # ${e.inlineComment}`;
        return line;
      }
      return "";
    }).join('\n');
  }

  /**
   * Generate Docker Compose environment block
   */
  function toDockerCompose(map) {
    if (!map || map.size === 0) return "# No environment variables";
    const lines = ["# Docker Compose Environment Block", "environment:"];
    map.forEach((val, key) => {
      lines.push(`  - ${key}=${val}`);
    });
    return lines.join('\n');
  }

  /**
   * Generate Kubernetes Secret YAML (stringData)
   */
  function toKubernetesSecret(map, secretName = "app-secrets") {
    if (!map || map.size === 0) return "# No environment variables";
    const lines = [
      `apiVersion: v1`,
      `kind: Secret`,
      `metadata:`,
      `  name: ${secretName}`,
      `type: Opaque`,
      `stringData:`
    ];
    map.forEach((val, key) => {
      // Escape quotes for YAML string
      const escaped = String(val).replace(/"/g, '\\"');
      lines.push(`  ${key}: "${escaped}"`);
    });
    return lines.join('\n');
  }

  /**
   * Generate GitHub Actions Secrets CLI Commands (gh secret set)
   */
  function toGitHubSecrets(map) {
    if (!map || map.size === 0) return "# No environment variables";
    const lines = ["# GitHub CLI Secret Set Commands", "# Requires GitHub CLI (gh auth login)"];
    map.forEach((val, key) => {
      const escaped = String(val).replace(/"/g, '\\"');
      lines.push(`gh secret set ${key} --body "${escaped}"`);
    });
    return lines.join('\n');
  }

  /**
   * Generate Terraform .tfvars
   */
  function toTerraformVars(map) {
    if (!map || map.size === 0) return "# No environment variables";
    const lines = ["# Terraform variables (.tfvars)"];
    map.forEach((val, key) => {
      const tfKey = key.toLowerCase();
      // Detect numbers vs strings
      if (/^-?\d+(\.\d+)?$/.test(val)) {
        lines.push(`${tfKey} = ${val}`);
      } else if (val.toLowerCase() === 'true' || val.toLowerCase() === 'false') {
        lines.push(`${tfKey} = ${val.toLowerCase()}`);
      } else {
        lines.push(`${tfKey} = "${String(val).replace(/"/g, '\\"')}"`);
      }
    });
    return lines.join('\n');
  }

  /**
   * Generate Passphrase-protected .env.vault (AES-256-GCM)
   */
  async function toEnvVault(rawContent, passphrase = "secret_passphrase", envName = "PRODUCTION") {
    const cryptoSubtle = (typeof window !== 'undefined' ? window.crypto : globalThis.crypto).subtle;
    const cryptoObj = (typeof window !== 'undefined' ? window.crypto : globalThis.crypto);
    const enc = new TextEncoder();
    const salt = cryptoObj.getRandomValues(new Uint8Array(16));
    const iv = cryptoObj.getRandomValues(new Uint8Array(12));

    const keyMaterial = await cryptoSubtle.importKey(
      "raw",
      enc.encode(passphrase),
      { name: "PBKDF2" },
      false,
      ["deriveKey"]
    );

    const key = await cryptoSubtle.deriveKey(
      {
        name: "PBKDF2",
        salt: salt,
        iterations: 100000,
        hash: "SHA-256"
      },
      keyMaterial,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt"]
    );

    const ciphertext = await cryptoSubtle.encrypt(
      { name: "AES-GCM", iv: iv },
      key,
      enc.encode(rawContent)
    );

    function toHex(buf) {
      return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    const saltHex = toHex(salt);
    const ivHex = toHex(iv);
    let binary = '';
    const bytes = new Uint8Array(ciphertext);
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    const ctBase64 = (typeof btoa !== 'undefined') ? btoa(binary) : Buffer.from(ciphertext).toString('base64');

    const vaultVal = `${saltHex}:${ivHex}:${ctBase64}`;
    const keyName = `DOTENV_VAULT_${envName.toUpperCase()}`;

    return `#/-------------------[DOTENV_VAULT]-------------------/
#/   Dotenv Vault Encrypted Environment Variables      /
#/   Standard PBKDF2 + AES-256-GCM Encrypted Vault    /
#/-----------------------------------------------------/
${keyName}="${vaultVal}"
`;
  }

  const exporters = {
    toExample,
    toDockerCompose,
    toKubernetesSecret,
    toGitHubSecrets,
    toTerraformVars,
    toEnvVault
  };

  if (typeof window !== 'undefined') {
    window.EnvExporters = exporters;
  }
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = exporters;
  }

  return exporters;

})();
