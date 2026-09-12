import { Link } from 'react-router-dom'
import { ShieldCheck } from 'lucide-react'
export default function Footer() { return <footer><div className="shell footer"><div className="footer-brand"><ShieldCheck size={18}/><b>PhishShield AI</b><span>AI-powered phishing URL analysis.</span></div><div className="footer-links"><Link to="/">Home</Link><Link to="/analyze">Analyze</Link><Link to="/how-it-works">How it works</Link><Link to="/history">History</Link></div><small>Built for Hackathon 2026</small></div></footer> }
