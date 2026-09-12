import { useState } from 'react'
import { ArrowRight, Link2, LoaderCircle, RotateCcw, X } from 'lucide-react'
import { demoChoices } from '../data/mockData'

const normalizeUrl = (value) => value.trim().match(/^https?:\/\//i) ? value.trim() : `https://${value.trim()}`
export default function URLAnalyzer({ onAnalyze, loading, error, onDemo }) {
  const [value, setValue] = useState('')
  const [validation, setValidation] = useState('')
  const submit = (event) => { event.preventDefault(); const url = normalizeUrl(value); try { const parsed = new URL(url); if (!parsed.hostname.includes('.')) throw new Error(); setValidation(''); setValue(url); onAnalyze(url, false) } catch { setValidation('Please enter a valid URL.') } }
  const useExample = (item) => { setValue(item.url); setValidation(''); onDemo(item.url) }
  return <section className="analyzer card"><div className="eyebrow"><span className="status-dot"></span> URL security scanner</div><h2>Analyze a suspicious URL</h2><p>We inspect URL structure only. The target webpage is never opened or executed.</p>
    <form onSubmit={submit}><label className="url-field"><Link2 size={20}/><input value={value} onChange={(e) => setValue(e.target.value)} placeholder="Paste a URL here..." aria-label="URL to analyze" autoComplete="url" disabled={loading}/>{value && <button type="button" className="clear" onClick={() => setValue('')} aria-label="Clear URL"><X size={17}/></button>}</label>{(validation || error) && <div className="error-message" role="alert">{validation || error}{error && <button type="button" onClick={() => onAnalyze(normalizeUrl(value), false)}><RotateCcw size={14}/> Try again</button>}</div>}
      <button className="button button-primary analyze-button" disabled={loading}>{loading ? <><LoaderCircle className="spin" size={18}/> Analyzing</> : <>Analyze URL <ArrowRight size={18}/></>}</button></form>
    <div className="demo-row"><span>Try a demo:</span>{demoChoices.map((item) => <button key={item.key} onClick={() => useExample(item)} disabled={loading}>{item.label}</button>)}</div>
  </section>
}
