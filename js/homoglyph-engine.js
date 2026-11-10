/**
 * SentinelOps - Homoglyph, Punycode & Typosquatting Detection Engine
 * Detects Unicode confusable characters, Punycode (IDN) spoofing,
 * Levenshtein distance, combosquatting, and brand impersonation.
 */

const HomoglyphEngine = (() => {
  // Common Cyrillic, Greek, and Unicode lookalikes mapping to Latin characters
  const CONFUSABLES = {
    // Cyrillic
    'а': 'a', 'А': 'A', 'с': 'c', 'С': 'C', 'е': 'e', 'Е': 'E',
    'о': 'o', 'О': 'O', 'р': 'p', 'Р': 'P', 'х': 'x', 'Х': 'X',
    'у': 'y', 'У': 'Y', 'і': 'i', 'І': 'I', 'ј': 'j', 'Ј': 'J',
    'ѕ': 's', 'Ѕ': 'S', 'ԁ': 'd', 'Ԃ': 'D', 'ԛ': 'q', 'Ԝ': 'W',
    'һ': 'h', 'Ӏ': 'l', 'ӏ': 'l', 'В': 'B', 'М': 'M', 'Н': 'H',
    'Т': 'T', 'К': 'K',
    // Greek
    'α': 'a', 'Α': 'A', 'β': 'b', 'Β': 'B', 'γ': 'y', 'ε': 'e',
    'Ε': 'E', 'η': 'n', 'Η': 'H', 'ι': 'i', 'Ι': 'I', 'κ': 'k',
    'Κ': 'K', 'ν': 'v', 'Ν': 'N', 'ο': 'o', 'Ο': 'O', 'ρ': 'p',
    'Ρ': 'P', 'τ': 't', 'Τ': 'T', 'χ': 'x', 'Χ': 'X',
    // Lookalike Latin visual twins (e.g. capital I vs lowercase l, digit 0 vs letter O)
    '1': 'l', '0': 'o', '5': 's', '8': 'b', '3': 'e', 'vv': 'w',
    // Invisible / zero-width characters
    '\u200B': '[ZERO_WIDTH_SPACE]',
    '\u200C': '[ZERO_WIDTH_NON_JOINER]',
    '\u200D': '[ZERO_WIDTH_JOINER]',
    '\uFEFF': '[ZERO_WIDTH_NO_BREAK_SPACE]',
    '\u00AD': '[SOFT_HYPHEN]'
  };

  // High-value global brand dictionary frequently targeted by phishing
  const TARGET_BRANDS = [
    { name: 'PayPal', domain: 'paypal.com', keywords: ['paypal', 'paypa1', 'paypai', 'pay-pal', 'paypol'] },
    { name: 'Microsoft', domain: 'microsoft.com', keywords: ['microsoft', 'office365', 'outlook', 'live', 'onedrive', 'sharepoint', 'azure'] },
    { name: 'Google', domain: 'google.com', keywords: ['google', 'gmail', 'googlemail', 'google-drive', 'gdrive', 'youtube'] },
    { name: 'Apple', domain: 'apple.com', keywords: ['apple', 'icloud', 'appleid', 'itunes', 'apple-support'] },
    { name: 'Amazon', domain: 'amazon.com', keywords: ['amazon', 'prime', 'aws', 'amazon-pay'] },
    { name: 'Meta / Facebook', domain: 'facebook.com', keywords: ['facebook', 'instagram', 'whatsapp', 'meta', 'fb-security'] },
    { name: 'Netflix', domain: 'netflix.com', keywords: ['netflix', 'netf1ix', 'net-flix'] },
    { name: 'Steam', domain: 'steampowered.com', keywords: ['steam', 'steampowered', 'steamcommunity', 'steam-gift'] },
    { name: 'Discord', domain: 'discord.com', keywords: ['discord', 'discord-nitro', 'discrod', 'dlscord', 'discordapp'] },
    { name: 'Telegram', domain: 'telegram.org', keywords: ['telegram', 't-me', 'telegam', 'telegrarn'] },
    { name: 'MetaMask', domain: 'metamask.io', keywords: ['metamask', 'metamask-io', 'metamusk', 'matamask'] },
    { name: 'Binance', domain: 'binance.com', keywords: ['binance', 'binance-us', 'binance-verify'] },
    { name: 'Coinbase', domain: 'coinbase.com', keywords: ['coinbase', 'coin-base', 'coinbace'] },
    { name: 'GitHub', domain: 'github.com', keywords: ['github', 'githvb', 'githup'] },
    { name: 'Chase Bank', domain: 'chase.com', keywords: ['chase', 'chasebank', 'chase-online'] },
    { name: 'Bank of America', domain: 'bankofamerica.com', keywords: ['bankofamerica', 'bofa', 'bank-of-america'] },
    { name: 'Wells Fargo', domain: 'wellsfargo.com', keywords: ['wellsfargo', 'wells-fargo'] },
    { name: 'DHL Express', domain: 'dhl.com', keywords: ['dhl', 'dhl-express', 'dhl-tracking', 'dhl-parcel'] },
    { name: 'FedEx', domain: 'fedex.com', keywords: ['fedex', 'fedex-tracking', 'fed-ex'] },
    { name: 'USPS', domain: 'usps.com', keywords: ['usps', 'usps-tracking', 'usps-delivery'] },
    { name: 'Twitter / X', domain: 'x.com', keywords: ['twitter', 'tw1tter', 'x-com'] },
    { name: 'Dropbox', domain: 'dropbox.com', keywords: ['dropbox', 'drop-box'] },
    { name: 'Adobe', domain: 'adobe.com', keywords: ['adobe', 'acrobat', 'adobesign'] },
    { name: 'DocuSign', domain: 'docusign.com', keywords: ['docusign', 'docu-sign'] },
    { name: 'Ledger', domain: 'ledger.com', keywords: ['ledger', 'ledger-live', 'ledgervault'] },
    { name: 'Trezor', domain: 'trezor.io', keywords: ['trezor', 'trezor-wallet'] },
    { name: 'Roblox', domain: 'roblox.com', keywords: ['roblox', 'robux', 'roblx'] }
  ];

  /**
   * Calculate Levenshtein Distance between two strings
   */
  function levenshtein(a, b) {
    if (a.length === 0) return b.length;
    if (b.length === 0) return a.length;
    const matrix = [];
    for (let i = 0; i <= b.length; i++) matrix[i] = [i];
    for (let j = 0; j <= a.length; j++) matrix[0][j] = j;

    for (let i = 1; i <= b.length; i++) {
      for (let j = 1; j <= a.length; j++) {
        if (b.charAt(i - 1) === a.charAt(j - 1)) {
          matrix[i][j] = matrix[i - 1][j - 1];
        } else {
          matrix[i][j] = Math.min(
            matrix[i - 1][j - 1] + 1, // substitution
            matrix[i][j - 1] + 1,     // insertion
            matrix[i - 1][j] + 1      // deletion
          );
        }
      }
    }
    return matrix[b.length][a.length];
  }

  /**
   * Scan text for non-ASCII or homoglyph characters
   */
  function inspectCharacters(str) {
    const findings = [];
    let normalized = '';
    let hasHomoglyphs = false;
    let hasInvisible = false;

    for (let i = 0; i < str.length; i++) {
      const char = str[i];
      const codePoint = char.codePointAt(0);

      if (CONFUSABLES[char]) {
        hasHomoglyphs = true;
        if (CONFUSABLES[char].startsWith('[ZERO_WIDTH')) {
          hasInvisible = true;
          findings.push({
            index: i,
            char: `[U+${codePoint.toString(16).toUpperCase().padStart(4, '0')}]`,
            type: 'invisible',
            description: `Invisible zero-width character detected at position ${i}`,
            replacement: ''
          });
        } else {
          findings.push({
            index: i,
            char: char,
            codePoint: `U+${codePoint.toString(16).toUpperCase().padStart(4, '0')}`,
            type: 'homoglyph',
            description: `'${char}' (U+${codePoint.toString(16).toUpperCase().padStart(4, '0')}) mimics Latin '${CONFUSABLES[char]}'`,
            replacement: CONFUSABLES[char]
          });
          normalized += CONFUSABLES[char];
        }
      } else {
        normalized += char;
      }
    }

    return {
      original: str,
      normalized: normalized,
      findings: findings,
      hasHomoglyphs: hasHomoglyphs,
      hasInvisible: hasInvisible
    };
  }

  /**
   * Check for visual tricks like uppercase 'I' replacing lowercase 'l'
   * e.g., 'paypaI' vs 'paypal'
   */
  function checkVisualSubstitutions(domain) {
    const raw = domain.toLowerCase();
    const originalWithCase = domain;
    const suspects = [];

    // Check if capital I was used in a lowercase domain representation (paypaI.com)
    if (/[A-Z]/.test(originalWithCase)) {
      const matches = originalWithCase.match(/[A-Z]/g);
      if (matches.includes('I')) {
        suspects.push({
          type: 'capital_I_for_l',
          detail: `Detected uppercase 'I' in domain '${originalWithCase}'. In sans-serif fonts, 'I' looks identical to lowercase 'l' (e.g. paypaI -> paypal).`
        });
      }
    }

    // Check digit substitutions: '0' for 'o', '1' for 'l' or 'i', 'rn' for 'm'
    if (raw.includes('0') && (raw.includes('g00gle') || raw.includes('micr0s0ft') || raw.includes('amaz0n'))) {
      suspects.push({
        type: 'digit_substitution',
        detail: `Digit '0' used to replace vowel 'o' in a known brand name.`
      });
    }

    if (raw.includes('rn') && (raw.includes('paypa1') || raw.includes('rnicros') || raw.includes('rneta'))) {
      suspects.push({
        type: 'rn_for_m',
        detail: `'rn' pair used to visually mimic letter 'm' in proportional fonts.`
      });
    }

    return suspects;
  }

  /**
   * Run full typosquatting check against known target brands
   */
  function checkTyposquatting(domain) {
    if (!domain) return { isImpersonating: false, details: [] };

    const cleanDomain = domain.toLowerCase().trim().replace(/^www\./, '');
    const sld = cleanDomain.split('.')[0]; // Second-level domain or hostname root
    const fullHost = cleanDomain;

    const charInspect = inspectCharacters(cleanDomain);
    const visualTricks = checkVisualSubstitutions(domain);
    const results = [];

    let highestRiskBrand = null;
    let minDistance = 999;
    let attackType = null;

    // Check each targeted brand
    for (const brand of TARGET_BRANDS) {
      const brandRoot = brand.domain.split('.')[0];

      // Exact match on legitimate domain?
      if (cleanDomain === brand.domain || cleanDomain.endsWith('.' + brand.domain)) {
        return {
          isImpersonating: false,
          isLegitimateBrandDomain: true,
          brand: brand.name,
          details: [`Verified exact domain match for official ${brand.name} (${brand.domain})`]
        };
      }

      // 1. Combosquatting: brand name embedded with hyphens/words (e.g. paypal-security, login-microsoft)
      for (const kw of brand.keywords) {
        if (cleanDomain.includes(kw)) {
          results.push({
            brand: brand.name,
            targetedDomain: brand.domain,
            type: 'combosquatting',
            matchedKeyword: kw,
            severity: 'HIGH',
            explanation: `Domain contains brand keyword '${kw}' combined with other terms, subdomains, or alternate TLD to deceive users into trusting it.`
          });
          break;
        }
      }

      // 2. Homoglyph check on normalized string
      if (charInspect.hasHomoglyphs) {
        const normSld = charInspect.normalized.split('.')[0];
        if (normSld.includes(brandRoot)) {
          results.push({
            brand: brand.name,
            targetedDomain: brand.domain,
            type: 'homoglyph_attack',
            severity: 'CRITICAL',
            explanation: `Punycode/IDN Homoglyph attack: Domain uses lookalike non-Latin characters to visually spoof '${brand.domain}'.`
          });
        }
      }

      // 3. Visual 'I' for 'l' check specifically for this brand
      if (domain.includes('I') && brandRoot.includes('l')) {
        const simulated = domain.replace(/I/g, 'l').toLowerCase();
        if (simulated.includes(brandRoot)) {
          results.push({
            brand: brand.name,
            targetedDomain: brand.domain,
            type: 'case_sensitive_font_typo',
            severity: 'CRITICAL',
            explanation: `Classic font-exploit typosquatting: Domain utilizes uppercase 'I' in place of lowercase 'l' to visually mimic official '${brand.domain}'.`
          });
        }
      }

      // 4. Levenshtein edit distance on SLD vs Brand root
      const dist = levenshtein(sld, brandRoot);
      if (dist > 0 && dist <= 2 && sld.length >= 4) {
        results.push({
          brand: brand.name,
          targetedDomain: brand.domain,
          type: 'levenshtein_typosquatting',
          distance: dist,
          severity: 'HIGH',
          explanation: `High-confidence typosquat: '${sld}' has an edit distance of only ${dist} character(s) from official '${brandRoot}'. Likely registered to catch user misspellings.`
        });
      }
    }

    // Check if domain starts with xn-- (Punycode)
    const isPunycode = cleanDomain.startsWith('xn--') || cleanDomain.includes('.xn--');

    return {
      isImpersonating: results.length > 0 || visualTricks.length > 0 || isPunycode,
      isLegitimateBrandDomain: false,
      isPunycode: isPunycode,
      charInspect: charInspect,
      visualTricks: visualTricks,
      findings: results,
      highestSeverity: results.some(r => r.severity === 'CRITICAL') ? 'CRITICAL' : (results.length > 0 ? 'HIGH' : 'LOW')
    };
  }

  return {
    CONFUSABLES,
    TARGET_BRANDS,
    levenshtein,
    inspectCharacters,
    checkVisualSubstitutions,
    checkTyposquatting
  };
})();

if (typeof module !== 'undefined' && module.exports) {
  module.exports = HomoglyphEngine;
}
