(function (root) {
  'use strict';
  function analyze(target) {
    var url = target.url, flags = target.brandMatches.length || target.unicode.suspicious || target.riskyTld || target.suspiciousTerms.length > 1;
    var hotspots = [
      { title:'Brand header & navigation', issue:flags ? 'Target hostname contains impersonation indicators; verify the brand and navigation links independently.' : 'The hostname alone does not establish brand authenticity.', severity:flags ? 'HIGH' : 'INFO', fix:'Navigate from an official brand website or a trusted bookmark; do not rely on logos or page styling.' },
      { title:'Urgency and social-engineering copy', issue:target.suspiciousTerms.length ? 'URL contains sensitive-action language (' + target.suspiciousTerms.slice(0,3).join(', ') + ').' : 'Page text is not available for inspection in this passive scan.', severity:target.suspiciousTerms.length ? 'MEDIUM' : 'UNKNOWN', fix:'Treat unsolicited deadlines and account warnings as untrusted; confirm through a separate official channel.' },
      { title:'Authentication forms & endpoints', issue:'Form fields and POST destinations cannot be inspected from the URL alone.', severity:'UNKNOWN', fix:'Do not enter credentials until the origin and form destination have been independently verified.' },
      { title:'External scripts & integrity', issue:'Page scripts and Subresource Integrity settings cannot be inspected from the URL alone.', severity:'UNKNOWN', fix:'Use browser developer tools or an authorized security scanner to examine scripts and integrity metadata.' }
    ];
    var headers = [
      { name:'Strict-Transport-Security', status:'Not checked', detail:'Response headers are not fetched by this browser-only scan.' },
      { name:'Content-Security-Policy', status:'Not checked', detail:'Cannot infer CSP from a URL.' },
      { name:'X-Frame-Options / frame-ancestors', status:'Not checked', detail:'Clickjacking protection requires inspecting the actual response headers.' },
      { name:'X-Content-Type-Options', status:'Not checked', detail:'MIME-sniffing protection requires inspecting the actual response headers.' },
      { name:'Referrer-Policy', status:'Not checked', detail:'No HTTP response was retrieved.' },
      { name:'Permissions-Policy', status:'Not checked', detail:'No HTTP response was retrieved.' }
    ];
    return { hostname:target.hostname, secureTransport:target.isHttps, grade:'N/A', note:'Passive URL-only analysis. This page does not load the target website or verify its headers.', hotspots:hotspots, headers:headers, cloned:flags, url:url.href };
  }
  root.WebsiteScanner = { analyze:analyze };
})(window);
