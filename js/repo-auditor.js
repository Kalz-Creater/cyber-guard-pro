(function (root) {
  'use strict';
  var api = 'https://api.github.com/repos/';
  function request(url, signal) {
    return fetch(url, { headers:{ Accept:'application/vnd.github+json', 'X-GitHub-Api-Version':'2022-11-28' }, signal:signal }).then(function (response) {
      if (!response.ok) {
        var error = new Error(response.status === 404 ? 'GitHub repository not found or is private.' : 'GitHub API returned HTTP ' + response.status + '.');
        error.status = response.status;
        throw error;
      }
      return response.json();
    });
  }
  function decodeContent(content) {
    var binary = atob(String(content || '').replace(/\s/g, '')), bytes = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return new TextDecoder('utf-8', { fatal:false }).decode(bytes);
  }
  function audit(owner, name) {
    var controller = new AbortController(), timer = setTimeout(function () { controller.abort(); }, 12000);
    var base = api + encodeURIComponent(owner) + '/' + encodeURIComponent(name);
    return request(base, controller.signal).then(function (repo) {
      var ageDays = Math.max(0, Math.floor((Date.now() - new Date(repo.created_at).getTime()) / 86400000));
      var risk = 0, findings = [];
      if (repo.archived) findings.push({ level:'info', title:'Repository is archived', detail:'Archived status is not a security verdict; verify that this is the intended source.' });
      if (ageDays < 30) { risk += 20; findings.push({ level:'warning', title:'Very recently created repository', detail:'Created less than 30 days ago. Independently validate the publisher and source before use.' }); }
      else if (ageDays < 180) { risk += 10; findings.push({ level:'info', title:'Limited repository history', detail:'Repository is less than six months old.' }); }
      if (repo.stargazers_count < 5 && ageDays < 365) { risk += 8; findings.push({ level:'warning', title:'Low adoption signal', detail:'Few stars on a young repository; popularity is only a weak signal and can be manipulated.' }); }
      if (!repo.license) findings.push({ level:'info', title:'No license metadata', detail:'Check the project terms before reusing its code.' });
      if (repo.description && /stealer|keylog|rat\b|crack|cheat|free.?aimbot|wallet.?drain/i.test(repo.description + ' ' + repo.name)) { risk += 45; findings.push({ level:'critical', title:'High-risk project description', detail:'Repository metadata uses terms strongly associated with credential theft, cheats, or wallet drainers. Do not execute its contents.' }); }
      if (!findings.length) findings.push({ level:'info', title:'No obvious metadata red flags', detail:'Metadata is not proof of safety. Review source, releases, maintainers, and dependency provenance.' });
      var result = { repo:repo, ageDays:ageDays, score:Math.max(5, 100 - Math.min(90, risk)), findings:findings, inspectedFiles:0, inspectionNote:'Public metadata and selected small build manifests are checked when the GitHub API permits; no code is executed.' };
      return request(base + '/contents', controller.signal).then(function (entries) {
        if (!Array.isArray(entries)) return result;
        var wanted = { 'package.json':true, 'setup.py':true, 'pyproject.toml':true, 'makefile':true, 'dockerfile':true };
        var candidates = entries.filter(function (entry) { return entry.type === 'file' && wanted[String(entry.name).toLowerCase()] && entry.size <= 262144; }).slice(0, 5);
        return Promise.all(candidates.map(function (entry) {
          return request(base + '/contents/' + encodeURIComponent(entry.name), controller.signal).then(function (file) {
            if (file.encoding !== 'base64' || typeof file.content !== 'string') return null;
            return { name:entry.name, text:decodeContent(file.content) };
          }).catch(function () { return null; });
        })).then(function (files) {
          files.filter(Boolean).forEach(function (file) {
            result.inspectedFiles++;
            var scan = root.PayloadInspector.scan(file.text);
            scan.findings.forEach(function (finding) {
              result.findings.push({ level:finding.severity, title:file.name + ': ' + finding.title, detail:'Static signature in a public build manifest: ' + finding.evidence.slice(0,140) + '. ' + finding.advice });
              result.score = Math.max(5, result.score - (finding.severity === 'critical' ? 35 : finding.severity === 'high' ? 22 : 10));
            });
          });
          if (result.inspectedFiles) result.inspectionNote = 'Public metadata and ' + result.inspectedFiles + ' selected build manifest(s) were inspected statically. No code was executed; findings are heuristic.';
          return result;
        });
      }).catch(function () { return result; });
    }).finally(function () { clearTimeout(timer); });
  }
  root.RepoAuditor = { audit:audit };
})(window);
