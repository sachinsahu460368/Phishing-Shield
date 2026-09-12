export const demoResults = {
  safe: {
    url: 'https://www.github.com/features/security', verdict: 'safe', risk_score: 18, confidence: 0.89,
    top_reasons: ['Uses a recognized HTTPS structure', 'No deceptive login keywords detected', 'URL structure is concise and consistent'],
    features: { url_length: 40, hostname_length: 14, num_dots: 2, num_hyphens: 0, num_subdomains: 1, path_length: 18, suspicious_keyword_count: 0, digit_ratio: 0, special_character_count: 4, entropy: 0.41, has_https: true, has_ip: false, has_port: false },
    processing_time_ms: 146, model_version: 'demo-v1.0'
  },
  suspicious: {
    url: 'https://account-notice-update.example.net/reset', verdict: 'suspicious', risk_score: 57, confidence: 0.76,
    top_reasons: ['Urgency-related keywords detected', 'Multiple hyphens in the hostname', 'Above-average URL complexity'],
    features: { url_length: 48, hostname_length: 33, num_dots: 2, num_hyphens: 2, num_subdomains: 1, path_length: 6, suspicious_keyword_count: 2, digit_ratio: 0.02, special_character_count: 6, entropy: 0.63, has_https: true, has_ip: false, has_port: false },
    processing_time_ms: 183, model_version: 'demo-v1.0'
  },
  phishing: {
    url: 'https://secure-login-example.com/verify', verdict: 'phishing', risk_score: 91, confidence: 0.91,
    top_reasons: ['Suspicious login keyword detected', 'High URL complexity', 'Multiple subdomains and separators'],
    features: { url_length: 84, hostname_length: 42, num_dots: 7, num_hyphens: 3, num_subdomains: 4, path_length: 35, suspicious_keyword_count: 3, digit_ratio: 0.08, special_character_count: 12, entropy: 0.72, has_https: true, has_ip: false, has_port: false },
    processing_time_ms: 221, model_version: 'demo-v1.0'
  }
}

export const demoChoices = [
  { key: 'safe', label: 'Safe example', url: demoResults.safe.url },
  { key: 'suspicious', label: 'Suspicious example', url: demoResults.suspicious.url },
  { key: 'phishing', label: 'Phishing example', url: demoResults.phishing.url },
]

export const demoForUrl = (url) => {
  const value = url.toLowerCase()
  if (value.includes('secure-login') || value.includes('verify')) return demoResults.phishing
  if (value.includes('notice') || value.includes('update') || value.includes('reset')) return demoResults.suspicious
  return { ...demoResults.safe, url }
}
