(function (root) {
  'use strict';
  var current = null, currentView = 'prompt', activeHotspot = 2, audioEnabled = true, scanNumber = 0;
  var hotspotIds = ['hotspot-wire-nav','hotspot-wire-banner','hotspot-wire-form','hotspot-wire-scripts'];
  var persona = {
    general:'Act as a defensive security analyst. Assess the indicators and explain uncertainty, likely risks, and safe verification steps.',
    devsecops:'Act as a DevSecOps reviewer. Focus on repository provenance, dependency and install-time risks, maintainer trust, and safe static review.',
    ecommerce:'Act as an e-commerce fraud analyst. Assess domain impersonation, fake-store indicators, payment risk, and consumer-safe next steps.',
    forensic:'Act as a digital forensics analyst. Separate observed evidence from inference, preserve provenance, and recommend safe collection steps.'
  };
  function byId(id) { return document.getElementById(id); }
  function escapeHtml(value) { return String(value == null ? '' : value).replace(/[&<>"']/g, function (c) { return ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' })[c]; }); }
  function delay(ms) { return new Promise(function (resolve) { setTimeout(resolve, ms); }); }
  function setText(id, value) { var node = byId(id); if (node) node.textContent = value == null ? '' : String(value); }
  function toggleHidden(id, hidden) { var node = byId(id); if (node) node.classList.toggle('hidden', !!hidden); }
  function toast(message, type) {
    var container = byId('toastContainer'); if (!container) return;
    var item = document.createElement('div');
    item.className = 'pointer-events-auto px-4 py-3 rounded-xl border shadow-lg font-mono text-xs bg-slate-950 ' + (type === 'error' ? 'border-rose-500/50 text-rose-300' : 'border-cyan-500/40 text-cyan-200');
    item.textContent = message; container.appendChild(item);
    setTimeout(function () { item.remove(); }, 3800);
  }
  function logLine(message, color) {
    var consoleNode = byId('scanConsoleLogs'); if (!consoleNode) return;
    var line = document.createElement('div'); line.className = color || 'text-slate-300';
    line.textContent = '[' + new Date().toLocaleTimeString() + '] ' + message;
    consoleNode.appendChild(line); consoleNode.scrollTop = consoleNode.scrollHeight;
  }
  function progress(value, stage) {
    var pct = Math.max(0, Math.min(100, value));
    setText('scanProgressPercent', pct + '%'); setText('currentScanStageText', stage);
    var bar = byId('scanProgressBar'); if (bar) bar.style.width = pct + '%';
  }
  function badge(id, text, tone) {
    var node = byId(id); if (!node) return;
    node.textContent = text;
    node.className = 'font-mono text-[11px] font-bold ' + (tone === 'bad' ? 'text-rose-400' : tone === 'warn' ? 'text-amber-400' : tone === 'info' ? 'text-cyan-400' : 'text-emerald-400');
  }
  function updateInputType() {
    var input = byId('targetInput'); if (!input) return;
    var value = input.value.trim(), github = /(?:^|\/)github\.com\//i.test(value), url = /^[a-z][a-z\d+.-]*:\/\//i.test(value);
    setText('detectedTypeBadge', github ? 'GITHUB REPO' : url ? 'FULL URL' : 'DOMAIN');
  }
  function loadPreset(value) {
    var input = byId('targetInput'); if (input) { input.value = value; updateInputType(); input.focus(); }
  }
  function switchResultView(view) {
    var names = ['prompt','website','specialist','homoglyph','sandbox'];
    currentView = names.indexOf(view) >= 0 ? view : 'prompt';
    names.forEach(function (name) {
      toggleHidden('resultView' + name.charAt(0).toUpperCase() + name.slice(1), name !== currentView);
      var tab = byId('viewTab' + name.charAt(0).toUpperCase() + name.slice(1));
      if (tab) tab.className = 'px-4 py-2 rounded-xl text-xs font-mono font-bold transition flex items-center gap-2 border ' + (name === currentView ? 'bg-cyan-500/20 text-cyan-400 border-cyan-500/50' : 'border-slate-800 bg-slate-900/60 text-slate-400 hover:text-slate-200');
    });
    if (root.lucide && root.lucide.createIcons) root.lucide.createIcons();
  }
  function colorName(score) { return score < 45 ? 'bad' : score < 75 ? 'warn' : 'good'; }
  function urlOutcome(target) {
    var result = UrlAnalyzer.score(target);
    return { score:result.score, reasons:result.reasons, findings:result.reasons.map(function (reason) { return { level:result.score < 45 ? 'critical' : result.score < 75 ? 'warning' : 'info', title:reason, detail:'Heuristic signal only; independently verify before taking action.' }; }), repo:null };
  }
  function setMetricText(id, value) { setText(id, value); }
  function renderHomoglyph(target) {
    var node = byId('homoglyphLabContainer'); if (!node) return;
    var result = target.unicode, chars = Array.from(target.hostname);
    var cards = chars.map(function (char, index) {
      var code = 'U+' + char.codePointAt(0).toString(16).toUpperCase().padStart(4,'0'), mapped = HomoglyphEngine.confusables[char];
      var suspicious = !!mapped || /[\u200B-\u200F\uFEFF\u2060]/.test(char);
      return '<div class="p-3 rounded-lg border ' + (suspicious ? 'border-rose-500/40 bg-rose-950/20' : 'border-slate-800 bg-slate-950/70') + ' text-center"><div class="text-2xl font-mono ' + (suspicious ? 'text-rose-300' : 'text-cyan-300') + '">' + escapeHtml(char) + '</div><div class="text-[10px] text-slate-500 font-mono">' + code + '</div><div class="text-[10px] text-slate-400">' + (mapped ? 'looks like ' + escapeHtml(mapped) : suspicious ? 'invisible character' : 'standard') + '</div></div>';
    }).join('');
    node.innerHTML = '<div class="p-4 rounded-xl border border-slate-800 bg-slate-950/70 space-y-2"><div class="text-xs font-mono text-slate-300">Hostname: <span class="text-cyan-300">' + escapeHtml(target.hostname) + '</span></div><div class="text-xs font-mono text-slate-400">Normalized lookalike: <span class="text-amber-300">' + escapeHtml(result.normalized) + '</span></div><div class="text-xs font-mono text-slate-400">ASCII/Punycode hostname: <span class="text-cyan-300">' + escapeHtml(result.asciiHostname || 'unavailable') + '</span> ' + (result.isPunycode ? '<span class="text-amber-300">(Punycode present)</span>' : '') + '</div></div><div class="grid grid-cols-3 sm:grid-cols-5 md:grid-cols-8 gap-2">' + (cards || '<p class="text-xs text-slate-400">No hostname characters available.</p>') + '</div><p class="text-xs text-slate-500 font-mono">' + result.confusables.length + ' confusable(s), ' + result.invisible.length + ' invisible character(s). Unicode detection is a heuristic and may produce false positives.</p>';
  }
  function renderWebsite(target) {
    var report = WebsiteScanner.analyze(target);
    setText('websiteHeaderGradeBadge', report.grade);
    setText('browserUrlDisplay', report.url);
    var lock = byId('browserLockIcon'); if (lock) lock.className = 'w-3 h-3 ' + (report.secureTransport ? 'text-cyan-400' : 'text-rose-400');
    setText('diagCloneStatus', report.cloned ? 'URL INDICATORS FOUND' : 'NOT DETERMINED');
    setText('diagClickjackingStatus', 'NOT CHECKED'); setText('diagSriStatus', 'NOT CHECKED');
    var grade = byId('websiteHeaderGradeBadge'); if (grade) grade.className = 'px-3 py-1 rounded-full text-xs font-mono font-bold bg-slate-700/40 text-slate-300 border border-slate-600';
    report.hotspots.forEach(function (item, index) {
      var badgeNode = byId('hotspot-badge-' + index);
      if (badgeNode) { badgeNode.textContent = item.severity; badgeNode.className = 'px-2 py-0.5 rounded text-[10px] font-mono border bg-slate-800 text-slate-300 border-slate-700'; }
    });
    var grid = byId('securityHeadersMatrixGrid');
    if (grid) grid.innerHTML = report.headers.map(function (header) { return '<div class="p-3 rounded-xl bg-slate-950/70 border border-slate-800"><div class="flex justify-between gap-2 text-xs font-mono"><span class="text-slate-200">' + escapeHtml(header.name) + '</span><span class="text-slate-400">' + escapeHtml(header.status) + '</span></div><p class="text-[11px] text-slate-500 mt-1">' + escapeHtml(header.detail) + '</p></div>'; }).join('');
    var hardening = '# Configure these on your own server; verify compatibility before deployment.\nadd_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;\nadd_header X-Content-Type-Options "nosniff" always;\nadd_header X-Frame-Options "DENY" always;\nadd_header Referrer-Policy "strict-origin-when-cross-origin" always;\n# Define a restrictive Content-Security-Policy for your application.';
    setText('hardeningConfigSnippet', hardening);
    selectWireframeHotspot(activeHotspot, report.hotspots);
    return report;
  }
  function selectWireframeHotspot(index, list) {
    activeHotspot = Math.max(0, Math.min(3, Number(index) || 0));
    var targetList = list || (current && current.website ? current.website.hotspots : null);
    hotspotIds.forEach(function (id, idx) { var node = byId(id); if (node) node.classList.toggle('ring-1', idx === activeHotspot); });
    if (!targetList) return;
    var item = targetList[activeHotspot]; if (!item) return;
    setText('inspectorElementTitle', item.title); setText('inspectorVulnName', item.issue); setText('inspectorDetailsText', item.issue); setText('inspectorFixText', item.fix);
    var severity = byId('inspectorSeverityBadge'); if (severity) { severity.textContent = item.severity; severity.className = 'px-2 py-0.5 rounded text-[10px] font-mono font-bold ' + (item.severity === 'HIGH' ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40' : 'bg-slate-800 text-slate-300 border border-slate-700'); }
  }
  function renderSpecialist(target, outcome) {
    var node = byId('specialistReportContainer'); if (!node) return;
    var indicators = outcome.findings.length ? outcome.findings.map(function (finding) { return '<li class="p-3 rounded-lg bg-slate-950/70 border border-slate-800"><span class="text-cyan-300 font-bold">' + escapeHtml(finding.title) + '</span><div class="text-xs text-slate-400 mt-1">' + escapeHtml(finding.detail) + '</div></li>'; }).join('') : '<li class="text-sm text-slate-400">No obvious URL indicators were found. This is not a guarantee of safety.</li>';
    node.innerHTML = '<div class="p-4 rounded-xl border border-slate-800 bg-slate-950/70"><h3 class="font-mono text-cyan-300 text-sm">Target & scope</h3><p class="text-xs text-slate-300 mt-2 break-all">' + escapeHtml(target.url.href) + '</p><p class="text-xs text-slate-500 mt-2">This is a client-side heuristic assessment. It does not verify DNS, WHOIS, TLS certificates, reputation feeds, or live page content.</p></div><div><h3 class="font-mono text-sm text-cyan-300 mb-2">Observed heuristic indicators</h3><ul class="space-y-2">' + indicators + '</ul></div><div class="p-4 rounded-xl border border-amber-500/20 bg-amber-950/10"><h3 class="font-mono text-sm text-amber-300">Recommended safe handling</h3><p class="text-xs text-slate-300 mt-2">Do not submit passwords, recovery phrases, payment information, or tokens. Verify the destination through an independent trusted channel. For repositories, inspect source and install scripts before use.</p></div>';
  }
  function renderResults(target, outcome) {
    current = { target:target, outcome:outcome, website:null };
    current.website = renderWebsite(target);
    var score = outcome.score, tone = colorName(score), title = score < 45 ? 'HIGH-RISK INDICATORS' : score < 75 ? 'REVIEW REQUIRED' : 'LOW-RISK SIGNALS';
    setText('scannedTargetDisplay', target.hostname); setText('verdictTitle', title); setText('verdictBadge', 'HEURISTIC ONLY'); setText('scoreValueText', score);
    setText('verdictSummaryText', score < 45 ? 'Several strong warning signals were found. Avoid interacting with this target and verify it independently.' : score < 75 ? 'Some warning signals merit manual review. This scan cannot establish that the target is safe.' : 'Few known warning signals were found. A high score is not a certification or guarantee of safety.');
    var circle = byId('scoreCirclePath'); if (circle) { circle.setAttribute('stroke-dasharray', score + ', 100'); circle.setAttribute('class', 'stroke-current transition-all duration-1000 ease-out ' + (tone === 'bad' ? 'text-rose-500' : tone === 'warn' ? 'text-amber-400' : 'text-emerald-500')); }
    var box = byId('verdictBox'); if (box) box.className = 'lg:col-span-5 glass-cyber rounded-2xl p-6 flex flex-col justify-between relative overflow-hidden border ' + (tone === 'bad' ? 'border-rose-500/50' : tone === 'warn' ? 'border-amber-500/40' : 'border-emerald-500/30');
    badge('metricSslBadge', target.isHttps ? 'HTTPS URL' : 'HTTP ONLY', target.isHttps ? 'info' : 'bad');
    setMetricText('metricSslText', target.isHttps ? 'HTTPS is used in the URL. This scanner did not validate the certificate or connection.' : 'The URL uses unencrypted HTTP. Do not send sensitive information.');
    badge('metricTypoBadge', target.unicode.suspicious || target.brandMatches.length ? 'REVIEW' : 'NO MATCH', target.unicode.suspicious || target.brandMatches.length ? 'bad' : 'good');
    setMetricText('metricTypoText', target.unicode.suspicious ? target.unicode.confusables.length + ' confusable and ' + target.unicode.invisible.length + ' invisible character(s) detected.' : target.brandMatches.length ? 'Possible brand impersonation: ' + target.brandMatches.join(', ') : 'No known Unicode confusable or brand indicator detected.');
    badge('metricAgeBadge', outcome.repo ? outcome.repo.ageDays + ' DAYS' : 'UNKNOWN', outcome.repo && outcome.repo.ageDays < 180 ? 'warn' : 'info');
    setMetricText('metricAgeText', outcome.repo ? 'GitHub repository creation date; this does not establish domain age or trust.' : 'Domain registration age and WHOIS data are not queried by this browser-only scan.');
    var flagCount = outcome.findings.length;
    badge('metricEngineBadge', flagCount + ' HEURISTIC FLAGS', flagCount ? 'warn' : 'good');
    setMetricText('metricEngineText', 'Local heuristics only. No antivirus engines or external threat-intelligence feeds were contacted.');
    var ghBox = byId('githubExtractedBox');
    if (outcome.repo) {
      toggleHidden('githubExtractedBox', false); setText('ghStarsCount', 'Stars: ' + Number(outcome.repo.stargazers_count || 0).toLocaleString());
      setText('ghMetadataDetails', 'Repo: ' + target.repo.owner + '/' + target.repo.name + ' | Language: ' + (outcome.repo.language || 'Not specified') + ' | Created: ' + new Date(outcome.repo.created_at).toLocaleDateString() + ' | Metadata only; source not executed.');
    } else if (ghBox) toggleHidden('githubExtractedBox', true);
    setText('specialistTabTitle', outcome.repo ? 'Repository Audit Report' : 'Specialist Intelligence Report');
    renderSpecialist(target, outcome); renderHomoglyph(target); updateGeneratedPrompt();
    toggleHidden('resultsDashboard', false);
    recordHistory(target, score, title);
    if (root.lucide && root.lucide.createIcons) root.lucide.createIcons();
  }
  function recordHistory(target, score, verdict) {
    var history = readHistory(); history = history.filter(function (item) { return item.raw !== target.raw; });
    history.unshift({ raw:target.raw, hostname:target.hostname, score:score, verdict:verdict, time:Date.now() });
    try { localStorage.setItem('cyberGuardHistory', JSON.stringify(history.slice(0,10))); } catch (_) {}
    renderHistory();
  }
  function readHistory() { try { var parsed = JSON.parse(localStorage.getItem('cyberGuardHistory') || '[]'); return Array.isArray(parsed) ? parsed.filter(function (item) { return item && typeof item.raw === 'string'; }) : []; } catch (_) { return []; } }
  function renderHistory() {
    var history = readHistory(), container = byId('historyListContainer'); setText('historyBadgeCount', history.length);
    if (!container) return; container.textContent = '';
    if (!history.length) { var empty = document.createElement('p'); empty.className = 'text-xs font-mono text-slate-500 text-center py-8'; empty.textContent = 'No scan history recorded yet.'; container.appendChild(empty); return; }
    history.forEach(function (record) {
      var button = document.createElement('button'); button.type = 'button'; button.className = 'w-full text-left p-3 rounded-xl bg-slate-900 border border-slate-800 hover:border-cyan-500/40'; button.dataset.target = record.raw;
      var name = document.createElement('span'); name.className = 'block text-xs font-mono text-cyan-300 truncate'; name.textContent = record.hostname || record.raw;
      var meta = document.createElement('span'); meta.className = 'block mt-1 text-[10px] font-mono text-slate-500'; meta.textContent = (record.verdict || 'Scanned') + ' - score ' + record.score + ' - ' + new Date(record.time).toLocaleString();
      button.appendChild(name); button.appendChild(meta); button.addEventListener('click', function () { loadPreset(button.dataset.target); closeHistory(); startAnalysis(); }); container.appendChild(button);
    });
  }
  function openHistory() { toggleHidden('historyBackdrop', false); if (byId('historyDrawer')) byId('historyDrawer').classList.remove('translate-x-full'); }
  function closeHistory() { toggleHidden('historyBackdrop', true); if (byId('historyDrawer')) byId('historyDrawer').classList.add('translate-x-full'); }
  function clearScanHistory() { try { localStorage.removeItem('cyberGuardHistory'); } catch (_) {} renderHistory(); toast('Scan history cleared.'); }
  function copyText(value, success) {
    var promise = navigator.clipboard && navigator.clipboard.writeText ? navigator.clipboard.writeText(value) : Promise.reject(new Error('Clipboard unavailable'));
    promise.then(function () { toast(success || 'Copied to clipboard.'); }).catch(function () {
      var field = document.createElement('textarea'); field.value = value; field.style.position = 'fixed'; field.style.opacity = '0'; document.body.appendChild(field); field.select();
      try { document.execCommand('copy'); toast(success || 'Copied to clipboard.'); } catch (_) { toast('Unable to access the clipboard. Select and copy the text manually.', 'error'); }
      field.remove();
    });
  }
  function updateGeneratedPrompt() {
    var box = byId('generatedPromptBox'); if (!box || !current) return;
    var scenario = byId('promptScenario'), role = scenario && persona[scenario.value] ? persona[scenario.value] : persona.general;
    var findings = current.outcome.findings.map(function (item) { return '- ' + item.title + ': ' + item.detail; }).join('\n') || '- No known local URL heuristic matched; absence of a match does not imply safety.';
    box.value = role + '\n\nTarget: ' + current.target.url.href + '\nScope: Client-side heuristic indicators only; no live content, WHOIS, certificate, or reputation feeds were verified.\n\nObserved indicators:\n' + findings + '\n\nPlease distinguish evidence from inference, identify false-positive possibilities, and give safe, non-destructive verification and remediation steps. Do not access, execute, or submit data to the target.';
  }
  function copyPromptToClipboard() { var box = byId('generatedPromptBox'); if (box) copyText(box.value, 'Prompt copied.'); }
  function copyHardeningConfig() { var node = byId('hardeningConfigSnippet'); if (node) copyText(node.textContent, 'Hardening configuration copied.'); }
  function copySpecialistMarkdown() {
    if (!current) return;
    var findings = current.outcome.findings.map(function (item) { return '- **' + item.title + '** - ' + item.detail; }).join('\n') || '- No known local URL heuristic matched.';
    copyText('# Defensive scan report\n\nTarget: ' + current.target.url.href + '\nHeuristic safety score: ' + current.outcome.score + '/100\n\n## Indicators\n' + findings + '\n\nThis client-side heuristic is not a safety certification. Verify through trusted channels.', 'Report copied as Markdown.');
  }
  function runSandboxScan() {
    var source = byId('sandboxCodeInput'), output = byId('sandboxScanOutput'); if (!source || !output) return;
    var result = PayloadInspector.scan(source.value);
    output.innerHTML = '<div class="p-3 rounded-xl border ' + (result.findings.length ? 'border-rose-500/40 bg-rose-950/10' : 'border-cyan-500/30 bg-slate-950/70') + '"><div class="font-mono text-xs text-cyan-300">' + escapeHtml(result.message) + ' (' + result.bytes + ' bytes)</div><p class="text-[11px] text-slate-500 mt-1">The snippet was never executed or sent anywhere. Static signatures are incomplete.</p></div>' + result.findings.map(function (finding) { return '<div class="p-3 rounded-xl bg-slate-950/70 border border-rose-500/30"><div class="text-xs font-mono text-rose-300 font-bold">' + escapeHtml(finding.severity.toUpperCase()) + ': ' + escapeHtml(finding.title) + '</div><pre class="text-[11px] text-slate-400 mt-2 whitespace-pre-wrap break-all">' + escapeHtml(finding.evidence) + '</pre><p class="text-xs text-slate-300 mt-2">' + escapeHtml(finding.advice) + '</p></div>'; }).join('');
  }
  function setAudio(enabled) {
    audioEnabled = enabled; setText('audioText', enabled ? 'SFX: ON' : 'SFX: OFF');
    var icon = byId('audioIcon'); if (icon) icon.setAttribute('data-lucide', enabled ? 'volume-2' : 'volume-x');
    if (root.lucide && root.lucide.createIcons) root.lucide.createIcons();
  }
  var sfx = { playScanSweep:function () {
    if (!audioEnabled) return;
    try { var Audio = root.AudioContext || root.webkitAudioContext; if (!Audio) return; var context = new Audio(), oscillator = context.createOscillator(), gain = context.createGain();
      oscillator.type = 'sine'; oscillator.frequency.setValueAtTime(440, context.currentTime); oscillator.frequency.exponentialRampToValueAtTime(880, context.currentTime + 0.12);
      gain.gain.setValueAtTime(0.035, context.currentTime); gain.gain.exponentialRampToValueAtTime(0.001, context.currentTime + 0.18);
      oscillator.connect(gain); gain.connect(context.destination); oscillator.start(); oscillator.stop(context.currentTime + 0.18); oscillator.onended = function () { context.close(); };
    } catch (_) {}
  } };
  async function startAnalysis() {
    var input = byId('targetInput'), button = byId('scanSubmitBtn'); if (!input) return;
    var target;
    try { target = UrlAnalyzer.analyze(input.value); } catch (error) { toast(error.message, 'error'); input.focus(); return; }
    var thisScan = ++scanNumber;
    if (button) button.disabled = true;
    toggleHidden('scanProgressSection', false); toggleHidden('resultsDashboard', true);
    var consoleNode = byId('scanConsoleLogs'); if (consoleNode) consoleNode.textContent = '';
    progress(8, 'Validating target format and parsing the hostname...'); logLine('Target parsed: ' + target.hostname, 'text-cyan-300');
    await delay(220); if (thisScan !== scanNumber) return;
    var outcome = urlOutcome(target);
    progress(30, 'Checking local Unicode and URL heuristics...'); logLine('Analyzing hostname, URL structure, and local indicators.');
    if (target.unicode.suspicious) logLine('Unicode/Punycode indicators detected.', 'text-amber-300');
    if (target.isGithub) {
      progress(48, 'Requesting public GitHub repository metadata...'); logLine('Fetching public metadata and selected build manifests for static review only.');
      try {
        var repoData = await RepoAuditor.audit(target.repo.owner, target.repo.name);
        if (thisScan !== scanNumber) return;
        outcome.repo = repoData.repo;
        outcome.findings = outcome.findings.concat(repoData.findings);
        outcome.score = Math.min(outcome.score, repoData.score);
        logLine('GitHub metadata reviewed; selected build manifests inspected without execution.', 'text-emerald-300');
      } catch (error) {
        logLine(error.name === 'AbortError' ? 'GitHub metadata request timed out; continuing with URL heuristics only.' : 'GitHub metadata unavailable: ' + error.message, 'text-amber-300');
        toast('Repository metadata could not be retrieved; showing URL-only heuristics.', 'error');
      }
    }
    if (thisScan !== scanNumber) return;
    progress(76, 'Preparing passive website and payload indicators...'); logLine('No target page content, certificate, WHOIS, or threat-feed lookup was performed.');
    await delay(200); if (thisScan !== scanNumber) return;
    progress(92, 'Generating report and local history...');
    renderResults(target, outcome); sfx.playScanSweep();
    logLine('Heuristic report ready. Score is not a safety guarantee.', 'text-emerald-300'); progress(100, 'Analysis complete. Review evidence and limitations.');
    if (button) button.disabled = false;
    await delay(650); if (thisScan === scanNumber) toggleHidden('scanProgressSection', true);
  }
  function tickClock() { var node = byId('headerUtcClock'); if (node) node.textContent = new Date().toISOString().slice(11,19) + ' UTC'; }
  function init() {
    updateInputType(); renderHistory(); tickClock(); setInterval(tickClock, 1000);
    var input = byId('targetInput'); if (input) input.addEventListener('input', updateInputType);
    var toggle = byId('toggleHistoryBtn'), close = byId('closeHistoryBtn'), backdrop = byId('historyBackdrop');
    if (toggle) toggle.addEventListener('click', openHistory); if (close) close.addEventListener('click', closeHistory); if (backdrop) backdrop.addEventListener('click', closeHistory);
    var audio = byId('toggleAudioBtn'); if (audio) audio.addEventListener('click', function () { setAudio(!audioEnabled); });
    if (root.lucide && root.lucide.createIcons) root.lucide.createIcons();
  }
  root.startAnalysis = startAnalysis; root.loadPreset = loadPreset; root.switchResultView = switchResultView;
  root.selectWireframeHotspot = selectWireframeHotspot; root.runSandboxScan = runSandboxScan;
  root.updateGeneratedPrompt = updateGeneratedPrompt; root.copyPromptToClipboard = copyPromptToClipboard;
  root.copyHardeningConfig = copyHardeningConfig; root.copySpecialistMarkdown = copySpecialistMarkdown;
  root.clearScanHistory = clearScanHistory; root.sfx = sfx;
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init); else init();
})(window);
