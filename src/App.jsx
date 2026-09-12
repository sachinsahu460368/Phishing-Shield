import { Route, Routes } from 'react-router-dom'
import Navbar from './components/Navbar'
import Footer from './components/Footer'
import Home from './pages/Home'
import Analyze from './pages/Analyze'
import History from './pages/History'
import HowItWorks from './pages/HowItWorks'
import { useTheme } from './hooks/useTheme'
export default function App() { const { theme, toggleTheme } = useTheme(); return <div className="app"><Navbar theme={theme} toggleTheme={toggleTheme}/><Routes><Route path="/" element={<Home/>}/><Route path="/analyze" element={<Analyze/>}/><Route path="/history" element={<History/>}/><Route path="/how-it-works" element={<HowItWorks/>}/></Routes><Footer/></div> }
