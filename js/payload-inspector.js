/**
 * SentinelOps - Static Payload & Script Inspector
 * Heuristic regex-based static analyzer for dangerous patterns in setup.py,
 * package.json, PowerShell, bash, and obfuscated snippets.
 */

const PayloadInspector = (() => {
  const SIGNATURES = [
    {
      id: 'DISCORD_WEBHOOK',
      severity: 'CRITICAL',
      category: 'Data Exfiltration',
      name: 'Hardcoded Discord Webhook Exfiltration URL',
      regex: /https:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/\d+\/[a-zA-Z0-9_\-]+/gi,
      advice: 'Legitimate code rarely hardcodes personal Discord webhooks. Infostealers use this to send stolen credentials.'
    },
    {
      id: 'TELEGRAM_BOT',
      severity: 'CRITICAL',
      category: 'Data Exfiltration',
      name: 'Hardcoded Telegram Bot Exfiltration Endpoint',
      regex: /https:\/\/api\.telegram\.org\/bot\d+:[a-zA-Z0-9_\-]+\/sendMessage/gi,
      advice: 'Adversaries utilize Telegram bots as C2 servers to exfiltrate victims\' data.'
    },
    {
      id: 'BASE64_EXEC',
      severity: 'CRITICAL',
      category: 'Memory Execution Obfuscation',
      name: 'Base64 Decoded String Piped to Exec/Eval',
      regex: /(?:exec|eval|os\.system|subprocess\.Popen)\s*\(\s*(?:base64\.b64decode|atob|Buffer\.from\([^)]*base64)/gi,
      advice: 'Decoding and executing base64 payloads at runtime hides malicious commands from static review.'
    },
    {
      id: 'NPM_LIFECYCLE_HOOK',
      severity: 'HIGH',
      category: 'Supply Chain Hook',
      name: 'Arbitrary Command in npm Lifecycle Script',
      regex: /"(?:preinstall|postinstall|install)"\s*:\s*"[^"]*(?:curl|wget|powershell|node -e|sh|bash)[^"]*"/gi,
      advice: 'Lifecycle scripts execute automatically when a developer runs `npm install`.'
    },
    {
      id: 'SETUPPY_CMDCLASS',
      severity: 'HIGH',
      category: 'Supply Chain Hook',
      name: 'Setuptools Custom Command Class Override',
      regex: /class\s+\w+\s*\(\s*(?:install|develop|build_py)\s*\):/gi,
      advice: 'Custom install classes in setup.py execute arbitrary python code during `pip install`.'
    },
    {
      id: 'PASS_PROTECTED_ZIP',
      severity: 'CRITICAL',
      category: 'AV Evasion',
      name: 'Password-Protected Archive Lure',
      regex: /(?:password|pass|pwd)\s*:\s*(?:1234|123|password|unpack)/gi,
      advice: 'Password-protected zip files in READMEs prevent automated malware scanners from unpacking payloads.'
    },
    {
      id: 'POWERSHELL_IEX',
      severity: 'CRITICAL',
      category: 'Malicious Shell Invocation',
      name: 'PowerShell Download Cradle (IEX / iwr)',
      regex: /(?:iex|invoke-expression)\s*(?:\(|&)?\s*(?:iwr|invoke-webrequest|new-object\s+net\.webclient)/gi,
      advice: 'Classic fileless malware cradle downloading and executing remote scripts in memory.'
    },
    {
      id: 'CURL_BASH',
      severity: 'HIGH',
      category: 'Remote Code Execution',
      name: 'Piped Shell Download (curl | bash)',
      regex: /(?:curl|wget)\s+[^|\n]+(?:\|\s*(?:bash|sh|zsh))/gi,
      advice: 'Executing unverified remote scripts directly into a shell allows full system compromise.'
    },
    {
      id: 'WALLET_TARGETING',
      severity: 'HIGH',
      category: 'Crypto Credential Theft',
      name: 'Targeting Browser Crypto Wallet Extensions',
      regex: /nkbihfbeogaeaoehlefnkodbefgpgknn|ibnejdfjmmkpcnlpebklmnkoeoihofec|bfnaelmomeimhlpmgjnjophhpkkoljpa/gi,
      advice: 'Reference to extension IDs for MetaMask, Phantom, or Ronin wallets. Infostealers extract local SQLite files.'
    }
  ];

  /**
   * Scan text snippet against security signatures
   */
  function scanSnippet(codeSnippet) {
    if (!codeSnippet || !codeSnippet.trim()) {
      return { matches: [], totalFindings: 0 };
    }

    const matches = [];

    for (const sig of SIGNATURES) {
      sig.regex.lastIndex = 0; // Reset regex cursor
      let match;
      while ((match = sig.regex.exec(codeSnippet)) !== null) {
        matches.push({
          id: sig.id,
          name: sig.name,
          category: sig.category,
          severity: sig.severity,
          matchedText: match[0],
          index: match.index,
          advice: sig.advice
        });
      }
    }

    return {
      matches: matches,
      totalFindings: matches.length,
      hasCritical: matches.some(m => m.severity === 'CRITICAL'),
      hasHigh: matches.some(m => m.severity === 'HIGH')
    };
  }

  return {
    SIGNATURES,
    scanSnippet
  };
})();

if (typeof module !== 'undefined' && module.exports) {
  module.exports = PayloadInspector;
}
