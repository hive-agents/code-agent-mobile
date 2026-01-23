import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App'
import './styles.css'

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
)

if (import.meta.env.PROD && 'serviceWorker' in navigator) {
  const hasExistingController = Boolean(navigator.serviceWorker.controller)
  let refreshing = false

  navigator.serviceWorker.addEventListener('controllerchange', () => {
    if (!hasExistingController || refreshing) {
      return
    }
    refreshing = true
    window.location.reload()
  })

  window.addEventListener('load', () => {
    navigator.serviceWorker
      .register('/sw.js')
      .then((registration) => {
        const triggerUpdate = () => {
          registration.update().catch(() => {})
        }

        if (registration.waiting && navigator.serviceWorker.controller) {
          registration.waiting.postMessage({ type: 'SKIP_WAITING' })
        }

        registration.addEventListener('updatefound', () => {
          const newWorker = registration.installing
          if (!newWorker) {
            return
          }
          newWorker.addEventListener('statechange', () => {
            if (
              newWorker.state === 'installed' &&
              navigator.serviceWorker.controller
            ) {
              newWorker.postMessage({ type: 'SKIP_WAITING' })
            }
          })
        })

        triggerUpdate()
        document.addEventListener('visibilitychange', () => {
          if (document.visibilityState === 'visible') {
            triggerUpdate()
          }
        })
        setInterval(triggerUpdate, 60 * 60 * 1000)
      })
      .catch(() => {})
  })
}
