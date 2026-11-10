(function (root) {
  'use strict';
  var knownBrands = ['paypal','google','microsoft','apple','amazon','facebook','instagram','netflix','github','coinbase','metamask','binance'];
  var riskyTlds = /\.(?:top|xyz|click|country|gq|tk|ml|cf|work|zip|mov)$/i;
  function nearMatch(a, b) {
    if (Math.abs(a.length - b.length) > 1) return false;
    var i = 0, j = 0, edits = 0;
    while (i < a.length && j < b.length) {
      if (a[i] === b[j]) { i++; j++; continue; }
      if (++edits > 1) return false;
      if (a.length > b.length) i++; else if (b.length > a.length) j++; else { i++; j++; }
    }
    return edits + (i < a.length || j < b.length ? 1 : 0) <= 1;
  }
  function analyze(value) {
    var raw = String(value || '').trim();
    if (!raw) throw new Error('Enter a URL, domain, or GitHub repository to scan.');
    if (/\s/.test(raw)) throw new Error('The target cannot contain spaces.');
    var url;
    try { url = new URL(/^[a-z][a-z\d+.-]*:\/\//i.test(raw) ? raw : 'https://' + raw); } catch (_) { throw new Error('That target is not a valid URL or domain.'); }
    if (url.protocol !== 'http:' && url.protocol !== 'https:') throw new Error('Only HTTP and HTTPS targets can be analyzed.');
    if (url.username || url.password) throw new Error('URLs containing embedded credentials are not accepted.');
    var hostname = url.hostname.toLowerCase().replace(/\.$/, ''), github = url.hostname.toLowerCase() === 'github.com', repo = null, segments = url.pathname.split('/').filter(Boolean);
    var rawHost = raw.replace(/^[a-z][a-z\d+.-]*:\/\//i, '').split(/[/?#]/)[0].split('@').pop().replace(/:\d+$/, '').replace(/\.$/, '');
    if (github && segments.length >= 2) repo = { owner:decodeURIComponent(segments[0]), name:decodeURIComponent(segments[1].split('@')[0]).replace(/\.git$/i,'') };
    var unicode = root.HomoglyphEngine.analyze(rawHost || hostname), hostText = unicode.normalized.toLowerCase(), brands = [];
    var tokens = hostText.split(/[^a-z0-9]+/).filter(Boolean);
    knownBrands.forEach(function (brand) {
      var official = hostname === brand + '.com' || hostname.endsWith('.' + brand + '.com');
      if (!official && tokens.some(function (token) { return token === brand || nearMatch(token, brand); })) brands.push(brand);
    });
    var suspiciousTerms = hostname.match(/login|verify|secure|account|update|support|wallet|airdrop|claim|bonus|password|signin/ig) || [];
    return { raw:raw, url:url, hostname:hostname, protocol:url.protocol, isHttps:url.protocol === 'https:', isGithub:github && !!repo, repo:repo, unicode:unicode, suspiciousTerms:suspiciousTerms, brandMatches:brands, riskyTld:riskyTlds.test(hostname), isIp:/^\d{1,3}(?:\.\d{1,3}){3}$/.test(hostname) || /^\[[0-9a-f:]+\]$/i.test(hostname), hasNonstandardPort:!!url.port, path:url.pathname + url.search };
  }
  function score(result) {
    var risk = 0, reasons = [];
    if (!result.isHttps) { risk += 14; reasons.push('The URL uses unencrypted HTTP.'); }
    if (result.unicode.suspicious) { risk += 25; reasons.push('Unicode confusables, invisible characters, or Punycode need review.'); }
    if (result.brandMatches.length) { risk += 22; reasons.push('The hostname resembles a protected brand (' + result.brandMatches.join(', ') + ').'); }
    if (result.riskyTld) { risk += 12; reasons.push('The top-level domain is commonly abused and merits scrutiny.'); }
    if (result.suspiciousTerms.length >= 2) { risk += 13; reasons.push('The hostname combines account or urgency-related terms.'); }
    else if (result.suspiciousTerms.length) { risk += 5; reasons.push('The hostname contains a sensitive-action term.'); }
    if (result.isIp) { risk += 12; reasons.push('The target is a raw IP address rather than a recognizable domain.'); }
    if (result.hasNonstandardPort) { risk += 8; reasons.push('The URL specifies a nonstandard port.'); }
    if (result.path.length > 1 && /login|signin|verify|wallet/i.test(result.path)) { risk += 8; reasons.push('The URL path references authentication or a wallet.'); }
    return { score:Math.max(5, 100 - Math.min(95, risk)), reasons:reasons };
  }
  root.UrlAnalyzer = { analyze:analyze, score:score };
})(window);
