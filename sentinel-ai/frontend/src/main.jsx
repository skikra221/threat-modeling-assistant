import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.jsx'

const STORAGE_KEY = 'theme'
const validThemes = new Set(['light', 'dark', 'system'])

const getSavedTheme = () => {
  const savedTheme = localStorage.getItem(STORAGE_KEY)
  return validThemes.has(savedTheme) ? savedTheme : 'system'
}

const applyTheme = (theme) => {
  const root = document.documentElement
  const systemPrefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches
  const resolvedTheme = theme === 'system' ? (systemPrefersDark ? 'dark' : 'light') : theme

  root.dataset.theme = resolvedTheme
  root.style.colorScheme = resolvedTheme
}

const setupTheme = () => {
  const initialTheme = getSavedTheme()
  applyTheme(initialTheme)

  const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)')
  const onSystemThemeChange = () => {
    if (getSavedTheme() === 'system') {
      applyTheme('system')
    }
  }

  if (typeof mediaQuery.addEventListener === 'function') {
    mediaQuery.addEventListener('change', onSystemThemeChange)
  } else {
    mediaQuery.addListener(onSystemThemeChange)
  }
}

setupTheme()

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
