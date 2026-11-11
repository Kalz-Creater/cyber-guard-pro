(function (root) {
  'use strict';
  var confusables = {
    '\u0391':'A','\u0410':'A','\u0392':'B','\u0412':'B','\u0421':'C','\u03f9':'C','\u0395':'E','\u0415':'E','\u0397':'H','\u041d':'H','\u0399':'I','\u0406':'I','\u0408':'J','\u039a':'K','\u041a':'K','\u039c':'M','\u041c':'M','\u039d':'N','\u039f':'O','\u041e':'O','\u03a1':'P','\u0420':'P','\u0405':'S','\u03a4':'T','\u0422':'T','\u03a7':'X','\u0425':'X','\u03a5':'Y','\u0423':'Y','\u0430':'a','\u03b1':'a','\u0435':'e','\u03b5':'e','\u043e':'o','\u03bf':'o','\u0440':'p','\u03c1':'p','\u0441':'c','\u0445':'x','\u0443':'y','\u0456':'i','\u04cf':'l','\u0131':'i','I':'l','\u2113':'l','\uFF10':'0','\uFF11':'1'
  };
  function analyze(value) {
    var text = String(value || ''), chars = Array.from(text), points = [], normalized = '', hidden = [];
    chars.forEach(function (char, index) {
      var code = char.codePointAt(0), replacement = confusables[char];
      var invisible = code === 0x200b || code === 0x200c || code === 0x200d || code === 0xfeff || code === 0x2060;
      if (invisible) hidden.push({ index:index, codePoint:'U+' + code.toString(16).toUpperCase().padStart(4,'0'), name:'Zero-width or invisible character' });
      if (replacement) points.push({ index:index, character:char, codePoint:'U+' + code.toString(16).toUpperCase().padStart(4,'0'), replacement:replacement });
      normalized += replacement || (invisible ? '' : char);
    });
    var host = '';
    try { host = new URL(/^[a-z][a-z\d+.-]*:\/\//i.test(text) ? text : 'https://' + text).hostname; } catch (_) {}
    var asciiHost = host;
    try { if (host && /[^\x00-\x7f]/.test(host)) asciiHost = new URL('http://' + host).hostname; } catch (_) {}
    return { input:text, normalized:normalized, confusables:points, invisible:hidden, hostname:host, asciiHostname:asciiHost, isPunycode:/^xn--/i.test(asciiHost) || asciiHost.split('.').some(function (part) { return /^xn--/i.test(part); }), suspicious:points.length > 0 || hidden.length > 0 || /xn--/i.test(asciiHost) };
  }
  root.HomoglyphEngine = { analyze:analyze, confusables:confusables };
})(window);
