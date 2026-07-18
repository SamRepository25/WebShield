import type { ScanResult } from './types';

function downloadFile(content: string, filename: string, mimeType: string) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

function sanitizeHostname(url: string): string {
  try {
    return new URL(url).hostname.replace(/[^a-z0-9.-]/gi, '_');
  } catch {
    return 'scan';
  }
}

export function exportJson(result: ScanResult): void {
  const json = JSON.stringify(result, null, 2);
  const filename = `webshield-${sanitizeHostname(result.url)}-${Date.now()}.json`;
  downloadFile(json, filename, 'application/json');
}

export function exportTextReport(result: ScanResult): void {
  const lines: string[] = [];
  lines.push('WebShield Security Report');
  lines.push('==========================');
  lines.push('');
  lines.push(`URL: ${result.url}`);
  if (result.finalUrl !== result.url) {
    lines.push(`Final URL: ${result.finalUrl}`);
  }
  lines.push(`Scanned: ${new Date(result.scannedAt).toLocaleString()}`);
  lines.push(`Duration: ${(result.scanDurationMs / 1000).toFixed(2)}s`);
  lines.push(`Score: ${result.score}/100 (Grade: ${result.grade})`);
  lines.push('');
  if (result.scoreBreakdown) {
    lines.push('Score Breakdown');
    lines.push('---------------');
    lines.push(`  Transport:      ${result.scoreBreakdown.transport.toFixed(1)}`);
    lines.push(`  Content:        ${result.scoreBreakdown.content.toFixed(1)}`);
    lines.push(`  Browser:        ${result.scoreBreakdown.browser.toFixed(1)}`);
    lines.push(`  Cookies:        ${result.scoreBreakdown.cookies.toFixed(1)}`);
    lines.push(`  Infrastructure: ${result.scoreBreakdown.infrastructure.toFixed(1)}`);
    lines.push('');
  }
  lines.push('HTTPS Status');
  lines.push('------------');
  lines.push(`Enabled: ${result.https.enabled ? 'Yes' : 'No'}`);
  lines.push(`HTTP Redirect: ${result.https.redirectFromHttp ? 'Yes' : 'No'}`);
  lines.push(`Valid Certificate: ${result.https.valid ? 'Yes' : 'No'}`);
  lines.push(`HSTS Preload Ready: ${result.https.hstsPreloadReady ? 'Yes' : 'No'}`);
  if (result.https.issuer) lines.push(`Issuer: ${result.https.issuer}`);
  if (result.https.protocol) lines.push(`Protocol: ${result.https.protocol}`);
  if (result.https.expiresAt) lines.push(`Expires: ${result.https.expiresAt}`);
  if (result.https.daysRemaining > 0) {
    lines.push(`Days Remaining: ${result.https.daysRemaining}`);
  }
  lines.push('');
  lines.push('Server Information');
  lines.push('------------------');
  lines.push(`Server: ${result.server.server || 'Hidden'}`);
  lines.push(`X-Powered-By: ${result.server.xPoweredBy || 'Hidden'}`);
  lines.push(`Compression: ${result.server.compression || 'None'}`);
  lines.push(`Final Status: HTTP ${result.server.finalStatusCode}`);
  lines.push(`Redirects: ${result.server.redirectCount}`);
  if (result.server.redirectChain.length > 1) {
    lines.push('Redirect Chain:');
    for (const step of result.server.redirectChain) {
      lines.push(`  ${step.status} ${step.https ? 'HTTPS' : 'HTTP'} ${step.url}`);
    }
  }
  lines.push('');
  if (result.cookies.length > 0) {
    lines.push('Cookie Security');
    lines.push('--------------');
    for (const cookie of result.cookies) {
      lines.push(`  ${cookie.name || '(unnamed)'}`);
      lines.push(`    Secure: ${cookie.secure ? 'Yes' : 'No'}`);
      lines.push(`    HttpOnly: ${cookie.httpOnly ? 'Yes' : 'No'}`);
      lines.push(`    SameSite: ${cookie.sameSite}`);
      if (cookie.weaknesses.length > 0) {
        lines.push(`    Weaknesses: ${cookie.weaknesses.join('; ')}`);
      }
    }
    lines.push('');
  }
  lines.push('Security Headers');
  lines.push('----------------');
  for (const header of result.headers) {
    lines.push(`  ${header.name}: ${header.status.toUpperCase()} (${header.pointsAwarded.toFixed(1)}/${header.maxPoints} pts)`);
    lines.push(`    Value: ${header.value}`);
    if (header.isWeak && header.weaknessReason) {
      lines.push(`    Weakness: ${header.weaknessReason}`);
    }
    lines.push('');
  }
  lines.push('Vulnerabilities');
  lines.push('---------------');
  lines.push(`  Total: ${result.vulnerabilities.count}`);
  lines.push(`  Critical: ${result.vulnerabilities.critical}`);
  lines.push(`  High: ${result.vulnerabilities.high}`);
  lines.push(`  Medium: ${result.vulnerabilities.medium}`);
  lines.push(`  Low: ${result.vulnerabilities.low}`);
  lines.push(`  Info: ${result.vulnerabilities.info}`);
  lines.push('');
  lines.push('Recommendations');
  lines.push('---------------');
  for (const rec of result.recommendations) {
    lines.push(`  [${rec.severity.toUpperCase()}] ${rec.title}`);
    lines.push(`    ${rec.description}`);
    lines.push(`    Example: ${rec.exampleImplementation}`);
    if (rec.references && rec.references.length > 0) {
      lines.push(`    References: ${rec.references.join(', ')}`);
    }
    lines.push('');
  }
  lines.push('Raw Headers');
  lines.push('----------');
  for (const header of result.rawHeaders) {
    lines.push(`  ${header.name}: ${header.value}`);
  }
  lines.push('');
  lines.push('---');
  lines.push('Generated by WebShield — https://webshield.app');

  const text = lines.join('\n');
  const filename = `webshield-${sanitizeHostname(result.url)}-${Date.now()}.txt`;
  downloadFile(text, filename, 'text/plain');
}

export function copyResults(result: ScanResult): Promise<void> {
  const text = formatResultsForSharing(result);
  return navigator.clipboard.writeText(text);
}

export function formatResultsForSharing(result: ScanResult): string {
  const lines: string[] = [];
  lines.push('WebShield Security Scan Results');
  lines.push('');
  lines.push(`URL: ${result.url}`);
  if (result.finalUrl !== result.url) {
    lines.push(`Final URL: ${result.finalUrl}`);
  }
  lines.push(`Score: ${result.score}/100 (Grade: ${result.grade})`);
  lines.push(`HTTPS: ${result.https.enabled ? 'Enabled' : 'Not Enabled'}`);
  lines.push(`HTTP Redirect: ${result.https.redirectFromHttp ? 'Yes' : 'No'}`);
  lines.push(`Headers: ${result.headers.filter((h) => h.status === 'present').length}/${result.headers.length} present`);
  lines.push(`Vulnerabilities: ${result.vulnerabilities.count} (${result.vulnerabilities.critical} critical, ${result.vulnerabilities.high} high, ${result.vulnerabilities.medium} medium, ${result.vulnerabilities.low} low, ${result.vulnerabilities.info} info)`);
  if (result.cookies.length > 0) {
    const insecure = result.cookies.filter((c) => c.weaknesses.length > 0).length;
    lines.push(`Cookies: ${result.cookies.length} (${insecure} with weaknesses)`);
  }
  lines.push('');
  if (result.recommendations.length > 0) {
    lines.push('Top Recommendations:');
    for (const rec of result.recommendations.slice(0, 3)) {
      lines.push(`  - [${rec.severity}] ${rec.title}`);
    }
  }
  lines.push('');
  lines.push('Scanned with WebShield — https://webshield.app');
  return lines.join('\n');
}

export async function shareResults(result: ScanResult): Promise<boolean> {
  const text = formatResultsForSharing(result);
  if (navigator.share) {
    try {
      await navigator.share({
        title: 'WebShield Security Scan',
        text,
      });
      return true;
    } catch {
      return false;
    }
  }
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}
