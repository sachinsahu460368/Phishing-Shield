export const APP_NAME = 'PhishShield AI'
export const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || ''
export const DEMO_MODE = import.meta.env.VITE_DEMO_MODE !== 'false'
export const RISK_THRESHOLDS = { low: 40, moderate: 70 }
export const HISTORY_KEY = 'phishshield-history'

export const riskMeta = (score = 0) => {
  if (score < RISK_THRESHOLDS.low) return { label: 'Low risk', tone: 'safe', description: 'No strong suspicious URL patterns detected.' }
  if (score < RISK_THRESHOLDS.moderate) return { label: 'Moderate risk', tone: 'suspicious', description: 'Review this URL carefully before continuing.' }
  return { label: 'High risk', tone: 'phishing', description: 'Avoid sharing details or proceeding to this URL.' }
}
