import { Link, NavLink } from 'react-router-dom'
import { Menu, Moon, ShieldCheck, Sun, X } from 'lucide-react'
import { useState } from 'react'

const links = [['/', 'Home'], ['/analyze', 'Analyze'], ['/how-it-works', 'How it works'], ['/history', 'History']]
export default function Navbar({ theme, toggleTheme }) {
  const [open, setOpen] = useState(false)
  return <header className="nav-wrap"><nav className="nav shell" aria-label="Main navigation">
    <Link className="brand" to="/" onClick={() => setOpen(false)}><span className="brand-mark"><ShieldCheck size={21}/></span><span>PhishShield <b>AI</b></span></Link>
    <div className="nav-links">{links.map(([to, label]) => <NavLink key={to} to={to} end={to === '/'}>{label}</NavLink>)}</div>
    <div className="nav-actions"><button className="icon-button" aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`} onClick={toggleTheme}>{theme === 'dark' ? <Sun size={18}/> : <Moon size={18}/>}</button><Link className="button button-primary nav-cta" to="/analyze">Analyze URL</Link><button className="menu-button" aria-label="Toggle navigation" onClick={() => setOpen(!open)}>{open ? <X/> : <Menu/>}</button></div>
    {open && <div className="mobile-menu">{links.map(([to, label]) => <NavLink key={to} to={to} end={to === '/'} onClick={() => setOpen(false)}>{label}</NavLink>)}<Link className="button button-primary" to="/analyze" onClick={() => setOpen(false)}>Analyze URL</Link></div>}
  </nav></header>
}
