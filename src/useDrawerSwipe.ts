import { useEffect, useRef, useCallback } from 'react'

type UseDrawerSwipeOptions = {
  drawerOpen: boolean
  setDrawerOpen: (open: boolean) => void
  drawerRef: React.RefObject<HTMLElement | null>
  disabled?: boolean
  edgeThreshold?: number
  swipeThreshold?: number
  velocityThreshold?: number
}

type SwipeState = {
  startX: number
  startY: number
  startTime: number
  currentX: number
  isTracking: boolean
  isEdgeSwipe: boolean
}

export function useDrawerSwipe({
  drawerOpen,
  setDrawerOpen,
  drawerRef,
  disabled = false,
  edgeThreshold = 25,
  swipeThreshold = 60,
  velocityThreshold = 0.4
}: UseDrawerSwipeOptions) {
  const stateRef = useRef<SwipeState>({
    startX: 0,
    startY: 0,
    startTime: 0,
    currentX: 0,
    isTracking: false,
    isEdgeSwipe: false
  })

  const handleTouchStart = useCallback((e: TouchEvent) => {
    if (disabled) return

    const touch = e.touches[0]
    const state = stateRef.current

    // For opening: detect edge swipe from left
    if (!drawerOpen && touch.clientX <= edgeThreshold) {
      state.isEdgeSwipe = true
      state.isTracking = true
      state.startX = touch.clientX
      state.startY = touch.clientY
      state.startTime = Date.now()
      state.currentX = touch.clientX
    }

    // For closing: detect swipe starting on drawer or scrim
    if (drawerOpen) {
      const drawer = drawerRef.current
      const isOnDrawer = drawer?.contains(e.target as Node)
      const isOnScrim = (e.target as HTMLElement)?.classList?.contains('scrim')

      if (isOnDrawer || isOnScrim) {
        state.isEdgeSwipe = false
        state.isTracking = true
        state.startX = touch.clientX
        state.startY = touch.clientY
        state.startTime = Date.now()
        state.currentX = touch.clientX
      }
    }
  }, [drawerOpen, disabled, edgeThreshold, drawerRef])

  const handleTouchMove = useCallback((e: TouchEvent) => {
    const state = stateRef.current
    if (!state.isTracking) return

    const touch = e.touches[0]
    const deltaX = touch.clientX - state.startX
    const deltaY = touch.clientY - state.startY

    // If vertical movement exceeds horizontal, cancel tracking (user is scrolling)
    if (Math.abs(deltaY) > Math.abs(deltaX) && Math.abs(deltaY) > 10) {
      state.isTracking = false
      return
    }

    state.currentX = touch.clientX
  }, [])

  const handleTouchEnd = useCallback(() => {
    const state = stateRef.current
    if (!state.isTracking) return

    const deltaX = state.currentX - state.startX
    const deltaTime = Date.now() - state.startTime
    const velocity = deltaTime > 0 ? Math.abs(deltaX) / deltaTime : 0

    // Opening gesture: swipe right from left edge
    if (!drawerOpen && state.isEdgeSwipe) {
      if (deltaX > swipeThreshold || (deltaX > 20 && velocity > velocityThreshold)) {
        setDrawerOpen(true)
      }
    }

    // Closing gesture: swipe left when drawer is open
    if (drawerOpen && deltaX < -swipeThreshold) {
      setDrawerOpen(false)
    }

    // Reset state
    state.isTracking = false
    state.isEdgeSwipe = false
  }, [drawerOpen, setDrawerOpen, swipeThreshold, velocityThreshold])

  useEffect(() => {
    document.addEventListener('touchstart', handleTouchStart, { passive: true })
    document.addEventListener('touchmove', handleTouchMove, { passive: true })
    document.addEventListener('touchend', handleTouchEnd)

    return () => {
      document.removeEventListener('touchstart', handleTouchStart)
      document.removeEventListener('touchmove', handleTouchMove)
      document.removeEventListener('touchend', handleTouchEnd)
    }
  }, [handleTouchStart, handleTouchMove, handleTouchEnd])
}
