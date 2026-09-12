import axios from 'axios'
import { API_BASE_URL, DEMO_MODE } from '../config'
import { demoForUrl } from '../data/mockData'

const client = axios.create({ baseURL: API_BASE_URL, timeout: 9000 })

const normalizeResult = (data, fallbackUrl) => ({
  url: data?.url || fallbackUrl,
  verdict: String(data?.verdict || 'suspicious').toLowerCase(),
  risk_score: Math.max(0, Math.min(100, Number(data?.risk_score ?? 0))),
  confidence: data?.confidence == null ? null : Number(data.confidence),
  top_reasons: Array.isArray(data?.top_reasons) ? data.top_reasons : [],
  features: data?.features && typeof data.features === 'object' ? data.features : {},
  processing_time_ms: data?.processing_time_ms,
  model_version: data?.model_version,
  timestamp: data?.timestamp || new Date().toISOString(),
})

export async function analyzeURL(url, { demo = false } = {}) {
  if (demo || DEMO_MODE) {
    await new Promise((resolve) => setTimeout(resolve, 850))
    return normalizeResult(demoForUrl(url), url)
  }
  try {
    const response = await client.post('/api/v1/analyze', { url })
    return normalizeResult(response.data, url)
  } catch (error) {
    const message = error.code === 'ECONNABORTED' ? 'The analysis request timed out. Please try again.' : 'Unable to analyze this URL right now.'
    throw new Error(message)
  }
}
