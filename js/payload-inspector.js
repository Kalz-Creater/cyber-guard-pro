(function (root) {
  'use strict';
  var signatures = [
    { id:'remote-shell', title:'Remote script piped to a shell', severity:'critical', pattern:/(?:curl|wget)\b[^\n|;]{0,180}\|\s*(?:sh|bash|zsh)\b/i, advice:'Do not run this command. Retrieve and inspect the referenced content in an isolated, disposable environment.' },
    { id:'encoded-execution', title:'Encoded content passed to an execution sink', severity:'critical', pattern:/(?:eval|exec|system|popen|subprocess\.run)\s*\([^\n]{0,180}(?:base64|b64decode|fromcharcode|atob)/i, advice:'Inspect the encoded data offline and trace every call path; this scanner does not decode or execute payloads.' },
    { id:'credential-access', title:'Potential credential or browser-data access', severity:'high', pattern:/(?:Login Data|Cookies|Local State|keyring|\.ssh\/id_|wallets?\.dat|seed phrase|credential[s]?\.dump)/i, advice:'Treat as sensitive-data access. Do not run; review the full source and report suspected theft.' },
    { id:'webhook-exfil', title:'Potential webhook or remote data exfiltration', severity:'high', pattern:/(?:discord(?:app)?\.com\/api\/webhooks|webhook\.site|requestbin|pastebin\.com\/raw|ngrok\.io)[^\s"']{0,180}/i, advice:'Verify the destination and data flow. Never send real credentials or tokens during testing.' },
    { id:'install-hook', title:'Package installation lifecycle hook', severity:'medium', pattern:/(?:"(?:preinstall|install|postinstall)"\s*:|\b(?:pre|post)?install\s*=|class\s+\w+\s*\([^)]*install)/i, advice:'Installation hooks run code as part of package setup. Read the referenced script and its dependencies before installing.' },
    { id:'persistence', title:'Potential persistence or security-control tampering', severity:'high', pattern:/(?:schtasks\s+\/create|RunOnce|LaunchAgents|crontab\s+-|DisableRealtimeMonitoring|iptables\s+-F)/i, advice:'Confirm this behavior is expected and authorized; inspect surrounding logic and execution context.' },
    { id:'obfuscation', title:'Encoded or dynamically constructed code', severity:'medium', pattern:/(?:powershell[^\n]{0,100}-enc(?:odedcommand)?\b|(?:from|import)\s+base64|String\.fromCharCode\s*\(|atob\s*\()/i, advice:'Obfuscation can conceal benign or harmful behavior. Analyze statically and never execute untrusted input.' }
  ];
  function scan(source) {
    var text = String(source || ''), findings = [];
    signatures.forEach(function (item) { var match = item.pattern.exec(text); if (match) findings.push({ id:item.id, title:item.title, severity:item.severity, evidence:match[0].slice(0,200), advice:item.advice }); });
    return { bytes:new Blob([text]).size, findings:findings, clean:findings.length === 0, message:findings.length ? findings.length + ' heuristic signal(s) found; manual review is required.' : 'No included heuristic signatures matched. This is not a guarantee of safety.' };
  }
  root.PayloadInspector = { scan:scan };
})(window);
