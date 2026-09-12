import { useState } from 'react'
import { ShieldCheck } from 'lucide-react'
import URLAnalyzer from '../components/URLAnalyzer'
import AnalysisLoader from '../components/AnalysisLoader'
import ResultCard from '../components/ResultCard'
import { analyzeURL } from '../services/api'
import { HISTORY_KEY } from '../config'

const saveHistory = (result) => { const prior = JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]').filter((item) => item.url !== result.url); localStorage.setItem(HISTORY_KEY, JSON.stringify([{ ...result, savedAt: new Date().toISOString() }, ...prior].slice(0, 20))) }
export default function Analyze() { const [result, setResult] = useState(null); const [loading, setLoading] = useState(false); const [error, setError] = useState(''); const run = async (url, demo) => { if (!url) return; setError(''); setLoading(true); try { const output = await analyzeURL(url, { demo }); setResult(output); saveHistory(output) } catch (err) { setError(err.message) } finally { setLoading(false) } }; return <main className="page shell"><div className="page-intro"><span className="eyebrow"><ShieldCheck size={15}/> Secure URL intelligence</span><h1>Analyze with confidence.</h1><p>Paste a link before you open it. We assess its structure only, never the destination page.</p></div><URLAnalyzer onAnalyze={run} onDemo={(url) => run(url, true)} loading={loading} error={error}/>{loading && <AnalysisLoader/>}{result && !loading && <ResultCard result={result}/>}</main> }
