import DOMPurify from 'dompurify'
import { marked } from 'marked'
import { hash as bcryptHash } from 'bcryptjs'
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'

type Block = {
  type: 'text' | 'tool_use' | 'tool_result' | 'reasoning' | 'attachment' | 'other'
  text?: string
  name?: string
  input?: string
}

type ChatMessage = {
  id: string
  role: 'user' | 'assistant' | 'tool' | 'meta'
  blocks: Block[]
  timestamp?: string
  meta?: {
    isMeta?: boolean
    reasoningStatus?: 'provided' | 'disabled' | 'unknown'
  }
}

type ConversationSummary = {
  sessionId: string
  project: string
  firstPrompt: string
  updatedAt: number
}

type ToolEntry = {
  id: string
  name: string
  input?: string
  result?: string
}

type FlatItem =
  | {
      kind: 'message'
      id: string
      role: ChatMessage['role']
      blocks: Block[]
      meta?: ChatMessage['meta']
      turn: number
    }
  | {
      kind: 'tool'
      tool: ToolEntry
      turn: number
    }

type DisplayItem =
  | {
      kind: 'message'
      id: string
      role: ChatMessage['role']
      blocks: Block[]
      meta?: ChatMessage['meta']
      isIntermediate?: boolean
    }
  | {
      kind: 'toolStack'
      id: string
      entries: StackEntry[]
    }

type StackEntry =
  | {
      kind: 'tool'
      tool: ToolEntry
    }
  | {
      kind: 'message'
      id: string
      role: ChatMessage['role']
      blocks: Block[]
      meta?: ChatMessage['meta']
    }

type Breadcrumb = {
  label: string
  path: string
}

type ServerPayload =
  | {
      type: 'bootstrap'
      currentProject: string | null
      conversations: ConversationSummary[]
      activeConversationId: string | null
      messages: ChatMessage[]
      model?: string | null
    }
  | {
      type: 'conversation'
      sessionId: string | null
      messages: ChatMessage[]
      currentProject?: string | null
      model?: string | null
    }
  | {
      type: 'dir_list'
      path: string
      parent: string | null
      entries: string[]
    }
  | { type: 'message'; message: ChatMessage }
  | { type: 'processing'; active: boolean }
  | { type: 'conversations'; conversations: ConversationSummary[] }
  | { type: 'error'; error: string }

type AuthStatus = {
  mode: 'off' | 'builtin' | 'external' | string
  authorized: boolean
  loginPath?: string
  logoutPath?: string
  salt?: string | null
}

const IS_SECURE_CONTEXT = window.location.protocol === 'https:'

const normalizeWebSocketUrl = (rawUrl: string) => {
  const url = new URL(rawUrl)
  if (url.protocol === 'http:') url.protocol = 'ws:'
  if (url.protocol === 'https:') url.protocol = 'wss:'
  if (IS_SECURE_CONTEXT && url.protocol === 'ws:') url.protocol = 'wss:'
  return url.toString()
}

const normalizeHttpOrigin = (rawUrl: string) => {
  const url = new URL(rawUrl)
  if (url.protocol === 'ws:') url.protocol = 'http:'
  if (url.protocol === 'wss:') url.protocol = 'https:'
  if (IS_SECURE_CONTEXT && url.protocol === 'http:') url.protocol = 'https:'
  return url.origin
}

const WS_URL = (() => {
  if (import.meta.env.VITE_WS_URL) {
    return normalizeWebSocketUrl(import.meta.env.VITE_WS_URL as string)
  }
  const protocol = IS_SECURE_CONTEXT ? 'wss' : 'ws'
  return `${protocol}://${window.location.hostname}:8787/cam-ws`
})()

const HTTP_BASE = (() => {
  if (import.meta.env.VITE_HTTP_URL) {
    return normalizeHttpOrigin(import.meta.env.VITE_HTTP_URL as string)
  }
  if (import.meta.env.VITE_WS_URL) {
    return normalizeHttpOrigin(import.meta.env.VITE_WS_URL as string)
  }
  const protocol = IS_SECURE_CONTEXT ? 'https' : 'http'
  return `${protocol}://${window.location.hostname}:8787`
})()

marked.setOptions({
  breaks: true,
  gfm: true,
  headerIds: false,
  mangle: false
})

function formatProject(project: string) {
  const parts = project.split('/').filter(Boolean)
  if (parts.length <= 2) return project
  return parts.slice(-2).join('/')
}

function truncateWords(text: string, maxWords = 10) {
  const words = text.trim().split(/\s+/)
  if (words.length <= maxWords) return text
  return `${words.slice(0, maxWords).join(' ')}...`
}

function resolveModelFromServer(model?: string | null) {
  if (!model) return null
  const normalized = model.trim().toLowerCase()
  if (normalized === 'opus-4.5' || normalized.includes('opus')) return 'opus-4.5'
  if (normalized === 'sonnet-4.5' || normalized.includes('sonnet')) return 'sonnet-4.5'
  return null
}

function renderMarkdown(text: string) {
  const html = marked.parse(text || '', { async: false }) as string
  return { __html: DOMPurify.sanitize(html) }
}

export default function App() {
  const [messages, setMessages] = useState<ChatMessage[]>([])
  const [conversations, setConversations] = useState<ConversationSummary[]>([])
  const [activeSessionId, setActiveSessionId] = useState<string | null>(null)
  const [currentProject, setCurrentProject] = useState<string | null>(null)
  const [drawerOpen, setDrawerOpen] = useState(false)
  const [projectPickerOpen, setProjectPickerOpen] = useState(false)
  const [dirPath, setDirPath] = useState<string | null>(null)
  const [dirParent, setDirParent] = useState<string | null>(null)
  const [dirEntries, setDirEntries] = useState<string[]>([])
  const [dirLoading, setDirLoading] = useState(false)
  const [dirError, setDirError] = useState<string | null>(null)
  const [authMode, setAuthMode] = useState<'off' | 'builtin' | 'external' | 'unknown'>('unknown')
  const [authAuthorized, setAuthAuthorized] = useState(true)
  const [authSalt, setAuthSalt] = useState<string | null>(null)
  const [authLoginPath, setAuthLoginPath] = useState('/cam-login')
  const [authStatusError, setAuthStatusError] = useState<string | null>(null)
  const [authStatusLoading, setAuthStatusLoading] = useState(true)
  const [loginPassword, setLoginPassword] = useState('')
  const [loginError, setLoginError] = useState<string | null>(null)
  const [loginPending, setLoginPending] = useState(false)
  const [searchOpen, setSearchOpen] = useState(false)
  const [searchQuery, setSearchQuery] = useState('')
  const [conversationSearchOpen, setConversationSearchOpen] = useState(false)
  const [conversationSearchQuery, setConversationSearchQuery] = useState('')
  const [modelMenuOpen, setModelMenuOpen] = useState(false)
  const [selectedModel, setSelectedModel] = useState<'opus-4.5' | 'sonnet-4.5'>('sonnet-4.5')
  const [expandedTools, setExpandedTools] = useState<Record<string, boolean>>({})
  const [expandedStacks, setExpandedStacks] = useState<Record<string, boolean>>({})
  const [isProcessing, setIsProcessing] = useState(false)
  const [inputText, setInputText] = useState('')
  const [planMode, setPlanMode] = useState(false)
  const [pendingFiles, setPendingFiles] = useState<{ name: string; content: string }[]>([])
  const [wsStatus, setWsStatus] = useState<'connecting' | 'open' | 'closed'>('connecting')
  const [isAtTop, setIsAtTop] = useState(true)
  const [isAtBottom, setIsAtBottom] = useState(true)

  const wsRef = useRef<WebSocket | null>(null)
  const scrollRef = useRef<HTMLDivElement | null>(null)
  const fileInputRef = useRef<HTMLInputElement | null>(null)
  const searchInputRef = useRef<HTMLInputElement | null>(null)
  const conversationSearchInputRef = useRef<HTMLInputElement | null>(null)

  const refreshAuthStatus = useCallback(async () => {
    setAuthStatusLoading(true)
    setAuthStatusError(null)
    try {
      const response = await fetch(`${HTTP_BASE}/cam-auth/status`, {
        method: 'GET',
        credentials: 'include'
      })
      if (!response.ok) {
        throw new Error('Auth status unavailable.')
      }
      const payload = (await response.json()) as AuthStatus
      setAuthMode(payload.mode === 'builtin' || payload.mode === 'external' || payload.mode === 'off' ? payload.mode : 'unknown')
      setAuthAuthorized(Boolean(payload.authorized))
      setAuthSalt(payload.salt ?? null)
      setAuthLoginPath(payload.loginPath ?? '/cam-login')
    } catch (error) {
      setAuthMode('unknown')
      setAuthAuthorized(true)
      setAuthSalt(null)
      setAuthStatusError('Auth status could not be loaded.')
    } finally {
      setAuthStatusLoading(false)
    }
  }, [])

  const connectWebSocket = useCallback(() => {
    if (wsRef.current) {
      wsRef.current.close()
    }
    setWsStatus('connecting')
    const ws = new WebSocket(WS_URL)
    wsRef.current = ws

    ws.onopen = () => {
      setWsStatus('open')
      ws.send(JSON.stringify({ type: 'init' }))
    }

    ws.onclose = () => {
      setWsStatus('closed')
    }

    ws.onmessage = (event) => {
      try {
        const payload = JSON.parse(event.data) as ServerPayload
        if (payload.type === 'bootstrap') {
          setCurrentProject(payload.currentProject)
          setConversations(payload.conversations)
          setActiveSessionId(payload.activeConversationId)
          setMessages(payload.messages)
          const resolvedModel = resolveModelFromServer(payload.model)
          if (resolvedModel) {
            setSelectedModel(resolvedModel)
          }
        }
        if (payload.type === 'conversation') {
          setActiveSessionId(payload.sessionId)
          setMessages(payload.messages)
          if (payload.currentProject !== undefined) {
            setCurrentProject(payload.currentProject)
          }
          const resolvedModel = resolveModelFromServer(payload.model)
          if (resolvedModel) {
            setSelectedModel(resolvedModel)
          }
        }
        if (payload.type === 'dir_list') {
          setDirPath(payload.path)
          setDirParent(payload.parent)
          setDirEntries(payload.entries)
          setDirLoading(false)
          setDirError(null)
        }
        if (payload.type === 'message') {
          setMessages((prev) => [...prev, payload.message])
        }
        if (payload.type === 'processing') {
          setIsProcessing(payload.active)
        }
        if (payload.type === 'conversations') {
          setConversations(payload.conversations)
        }
        if (payload.type === 'error') {
          setMessages((prev) => [
            ...prev,
            {
              id: `error-${Date.now()}`,
              role: 'meta',
              blocks: [{ type: 'text', text: payload.error }]
            }
          ])
        }
      } catch (error) {
        setMessages((prev) => [
          ...prev,
          {
            id: `error-${Date.now()}`,
            role: 'meta',
            blocks: [{ type: 'text', text: 'Server message could not be parsed.' }]
          }
        ])
      }
    }
  }, [])

  useEffect(() => {
    refreshAuthStatus()
  }, [refreshAuthStatus])

  useEffect(() => {
    const root = document.documentElement
    const updateViewportWidth = () => {
      const width = window.visualViewport?.width ?? window.innerWidth
      root.style.setProperty('--app-vw', `${Math.round(width)}px`)
    }

    updateViewportWidth()
    window.addEventListener('resize', updateViewportWidth)
    window.visualViewport?.addEventListener('resize', updateViewportWidth)
    window.visualViewport?.addEventListener('scroll', updateViewportWidth)
    return () => {
      window.removeEventListener('resize', updateViewportWidth)
      window.visualViewport?.removeEventListener('resize', updateViewportWidth)
      window.visualViewport?.removeEventListener('scroll', updateViewportWidth)
      root.style.removeProperty('--app-vw')
    }
  }, [])

  useEffect(() => {
    if (authStatusLoading) return
    if (authMode === 'builtin' && !authAuthorized) return
    connectWebSocket()
    return () => {
      wsRef.current?.close()
    }
  }, [authStatusLoading, authMode, authAuthorized, connectWebSocket])

  useEffect(() => {
    const ua = navigator.userAgent
    const isIOS = /iPad|iPhone|iPod/.test(ua) || (ua.includes('Mac') && 'ontouchend' in document)
    if (!isIOS) return
    const meta = document.querySelector<HTMLMetaElement>('meta[name="viewport"]')
    if (!meta) return
    const baseContent = 'width=device-width, initial-scale=1, viewport-fit=cover'
    if (meta.content !== baseContent) {
      meta.content = baseContent
    }

    let resetId: number | null = null
    const resetViewport = () => {
      const viewport = window.visualViewport
      if (!viewport || viewport.scale <= 1) return
      // iOS Safari can stick at a zoomed scale after inputs blur.
      meta.content = `${baseContent}, maximum-scale=1`
      if (resetId !== null) window.clearTimeout(resetId)
      resetId = window.setTimeout(() => {
        meta.content = baseContent
      }, 80)
    }

    const handleFocusOut = () => {
      window.setTimeout(resetViewport, 0)
    }

    window.addEventListener('focusout', handleFocusOut)
    window.addEventListener('orientationchange', resetViewport)
    return () => {
      window.removeEventListener('focusout', handleFocusOut)
      window.removeEventListener('orientationchange', resetViewport)
      if (resetId !== null) window.clearTimeout(resetId)
    }
  }, [])

  const updateScrollState = useCallback(() => {
    const node = scrollRef.current
    if (!node) return
    const threshold = 12
    const atTop = node.scrollTop <= threshold
    const atBottom = node.scrollTop + node.clientHeight >= node.scrollHeight - threshold
    setIsAtTop(atTop)
    setIsAtBottom(atBottom)
  }, [])

  useEffect(() => {
    const node = scrollRef.current
    if (!node) return
    const handleScroll = () => updateScrollState()
    updateScrollState()
    node.addEventListener('scroll', handleScroll, { passive: true })
    window.addEventListener('resize', updateScrollState)
    return () => {
      node.removeEventListener('scroll', handleScroll)
      window.removeEventListener('resize', updateScrollState)
    }
  }, [updateScrollState])

  useEffect(() => {
    const node = scrollRef.current
    if (!node) return
    node.scrollTop = node.scrollHeight
    updateScrollState()
  }, [messages, isProcessing, updateScrollState])

  useEffect(() => {
    if (searchOpen) {
      searchInputRef.current?.focus()
    }
  }, [searchOpen])

  useEffect(() => {
    if (conversationSearchOpen) {
      conversationSearchInputRef.current?.focus()
    }
  }, [conversationSearchOpen])

  const canSend = useMemo(() => {
    return inputText.trim().length > 0 || pendingFiles.length > 0
  }, [inputText, pendingFiles])

  const uniqueConversations = useMemo(() => {
    const sorted = [...conversations].sort((a, b) => b.updatedAt - a.updatedAt)
    const map = new Map<string, ConversationSummary>()
    for (const conversation of sorted) {
      if (!map.has(conversation.sessionId)) {
        map.set(conversation.sessionId, conversation)
      }
    }
    return Array.from(map.values())
  }, [conversations])

  const filteredConversations = useMemo(() => {
    const query = conversationSearchQuery.trim().toLowerCase()
    if (!query) return uniqueConversations
    return uniqueConversations.filter((conversation) => {
      const haystack = `${conversation.firstPrompt} ${conversation.project} ${conversation.sessionId}`.toLowerCase()
      return haystack.includes(query)
    })
  }, [conversationSearchQuery, uniqueConversations])

  const filteredDirEntries = useMemo(() => {
    const query = searchQuery.trim().toLowerCase()
    if (!query) return dirEntries
    return dirEntries.filter((entry) => entry.toLowerCase().includes(query))
  }, [dirEntries, searchQuery])

  const breadcrumbs = useMemo(() => {
    if (!dirPath) return [] as Breadcrumb[]
    const normalized = dirPath.replace(/\/+/g, '/')
    const parts = normalized.split('/').filter(Boolean)
    const items: Breadcrumb[] = []
    let current = normalized.startsWith('/') ? '' : ''
    for (const part of parts) {
      current = current ? `${current}/${part}` : normalized.startsWith('/') ? `/${part}` : part
      items.push({ label: part, path: current })
    }
    return items
  }, [dirPath])

  const requestDirList = (path: string | null, options: { resetSearch?: boolean } = {}) => {
    if (options.resetSearch) {
      setSearchQuery('')
    }
    setDirLoading(true)
    setDirError(null)
    setDirEntries([])
    setDirParent(null)
    wsRef.current?.send(JSON.stringify({ type: 'list_dirs', path }))
  }

  const sendMessage = () => {
    if (!canSend) return
    const payload = {
      type: 'send_prompt',
      text: inputText.trim(),
      attachments: pendingFiles,
      model: selectedModel,
      planMode
    }
    wsRef.current?.send(JSON.stringify(payload))
    setInputText('')
    setPendingFiles([])
  }

  const handleKeyDown: React.KeyboardEventHandler<HTMLTextAreaElement> = (event) => {
    if (event.key === 'Enter' && !event.shiftKey) {
      event.preventDefault()
      sendMessage()
    }
  }

  const handleFileChange: React.ChangeEventHandler<HTMLInputElement> = async (event) => {
    const files = event.target.files
    if (!files) return
    const next: { name: string; content: string }[] = []
    for (const file of Array.from(files)) {
      const text = await file.text()
      next.push({ name: file.name, content: text })
    }
    setPendingFiles((prev) => [...prev, ...next])
    event.target.value = ''
  }

  const handleSelectConversation = (conversation: ConversationSummary) => {
    wsRef.current?.send(
      JSON.stringify({
        type: 'select_conversation',
        sessionId: conversation.sessionId,
        project: conversation.project
      })
    )
    setDrawerOpen(false)
    setConversationSearchOpen(false)
    setConversationSearchQuery('')
    setModelMenuOpen(false)
  }

  const handleNewConversation = () => {
    setDrawerOpen(false)
    setConversationSearchOpen(false)
    setConversationSearchQuery('')
    setModelMenuOpen(false)
    setProjectPickerOpen(true)
    setSearchOpen(false)
    setSearchQuery('')
    requestDirList(null)
  }

  const handleClosePicker = () => {
    setProjectPickerOpen(false)
    setSearchOpen(false)
    setSearchQuery('')
  }

  const handleNavigateDir = (entry: string) => {
    if (!dirPath) return
    requestDirList(`${dirPath}/${entry}`, { resetSearch: true })
  }

  const handleUseFolder = () => {
    if (!dirPath) return
    wsRef.current?.send(JSON.stringify({ type: 'new_conversation', project: dirPath }))
    setMessages([])
    setActiveSessionId(null)
    setCurrentProject(dirPath)
    setProjectPickerOpen(false)
    setSearchOpen(false)
    setSearchQuery('')
  }

  const handleToggleSearch = () => {
    setSearchOpen((prev) => !prev)
  }

  const handleClearSearch = () => {
    setSearchQuery('')
  }

  const handleToggleConversationSearch = () => {
    setModelMenuOpen(false)
    setConversationSearchOpen((prev) => {
      const next = !prev
      if (!next) {
        setConversationSearchQuery('')
      }
      return next
    })
  }

  const handleClearConversationSearch = () => {
    setConversationSearchQuery('')
  }

  const handleSelectModel = (model: 'opus-4.5' | 'sonnet-4.5') => {
    setSelectedModel(model)
    setModelMenuOpen(false)
  }

  const handleLoginSubmit: React.FormEventHandler<HTMLFormElement> = async (event) => {
    event.preventDefault()
    if (!authSalt) {
      setLoginError('Login is not ready yet.')
      return
    }
    if (!loginPassword.trim()) {
      setLoginError('Enter your password.')
      return
    }
    setLoginPending(true)
    setLoginError(null)
    try {
      const hash = await bcryptHash(loginPassword, authSalt)
      const response = await fetch(`${HTTP_BASE}${authLoginPath}`, {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ hash })
      })
      if (!response.ok) {
        if (response.status === 401) {
          throw new Error('Password not accepted.')
        }
        if (response.status === 404) {
          throw new Error(`Login endpoint not found. Check proxy for ${authLoginPath}.`)
        }
        if (response.status === 500) {
          throw new Error(
            'Server auth is not configured. Set CAM_AUTH_PASSWORD_BCRYPT and CAM_AUTH_SIGNING_SECRET.'
          )
        }
        const detail = await response.text()
        throw new Error(`Login failed (${response.status}). ${detail || ''}`.trim())
      }
      setLoginPassword('')
      await refreshAuthStatus()
    } catch (error) {
      const message =
        error instanceof Error ? error.message : 'Login failed.'
      setLoginError(message)
    } finally {
      setLoginPending(false)
    }
  }

  const scrollToTop = () => {
    const node = scrollRef.current
    if (!node) return
    node.scrollTo({ top: 0, behavior: 'smooth' })
  }

  const scrollToBottom = () => {
    const node = scrollRef.current
    if (!node) return
    node.scrollTo({ top: node.scrollHeight, behavior: 'smooth' })
  }

  const toggleTool = (id: string) => {
    setExpandedTools((prev) => ({ ...prev, [id]: !prev[id] }))
  }

  const toggleStack = (id: string) => {
    setExpandedStacks((prev) => ({ ...prev, [id]: !prev[id] }))
  }

  const displayItems = useMemo(() => {
    const flatItems: FlatItem[] = []
    const pendingTools: ToolEntry[] = []
    let toolIndex = 0
    let messageIndex = 0
    let currentTurn = -1

    const filterBlocks = (blocks: Block[]) => {
      return blocks.filter((block) => {
        if (block.type === 'text' || block.type === 'reasoning' || block.type === 'other') {
          return Boolean(block.text && block.text.trim())
        }
        if (block.type === 'attachment') {
          const hasText = Boolean(block.text && block.text.trim())
          return Boolean(block.name || hasText)
        }
        return false
      })
    }

    for (const message of messages) {
      if (message.role === 'user') {
        currentTurn += 1
      }
      if (currentTurn < 0) currentTurn = 0
      let segmentBlocks: Block[] = []
      let segmentIndex = 0

      const flushSegment = () => {
        const filteredBlocks = filterBlocks(segmentBlocks)
        if (filteredBlocks.length === 0) {
          segmentBlocks = []
          return
        }
        flatItems.push({
          kind: 'message',
          id: `${message.id}-${messageIndex}-${segmentIndex}`,
          role: message.role,
          blocks: filteredBlocks,
          meta: message.meta,
          turn: currentTurn
        })
        messageIndex += 1
        segmentIndex += 1
        segmentBlocks = []
      }

      message.blocks.forEach((block, blockIndex) => {
        if (block.type === 'tool_use') {
          flushSegment()
          const tool: ToolEntry = {
            id: `${message.id}-tool-${blockIndex}-${toolIndex}`,
            name: block.name ?? 'unknown',
            input: block.input
          }
          toolIndex += 1
          pendingTools.push(tool)
          flatItems.push({ kind: 'tool', tool, turn: currentTurn })
          return
        }
        if (block.type === 'tool_result') {
          flushSegment()
          const target = pendingTools.shift()
          if (target) {
            target.result = block.text ?? ''
          } else {
            const tool: ToolEntry = {
              id: `${message.id}-tool-${blockIndex}-${toolIndex}`,
              name: 'unknown',
              result: block.text ?? ''
            }
            toolIndex += 1
            flatItems.push({ kind: 'tool', tool, turn: currentTurn })
          }
          return
        }
        segmentBlocks.push(block)
      })

      flushSegment()
    }

    const lastTurn = currentTurn < 0 ? 0 : currentTurn
    const turnHasTools = new Map<number, boolean>()
    const turnLastAssistantIndex = new Map<number, number>()

    flatItems.forEach((item, index) => {
      if (item.kind === 'tool') {
        turnHasTools.set(item.turn, true)
        return
      }
      if (item.role === 'assistant') {
        turnLastAssistantIndex.set(item.turn, index)
      }
    })

    const stackedItems: DisplayItem[] = []
    let stack: StackEntry[] = []
    let stackIndex = 0

    const flushStack = () => {
      if (stack.length === 0) return
      stackedItems.push({ kind: 'toolStack', id: `stack-${stackIndex}`, entries: stack })
      stackIndex += 1
      stack = []
    }

    flatItems.forEach((item, index) => {
      if (item.kind === 'tool') {
        stack.push({ kind: 'tool', tool: item.tool })
        return
      }

      const hasTools = turnHasTools.get(item.turn) === true
      const isAssistant = item.role === 'assistant'
      const isLastAssistant = turnLastAssistantIndex.get(item.turn) === index
      const isIntermediate = hasTools && isAssistant && !isLastAssistant
      const isActiveTurn = isProcessing && item.turn === lastTurn

      if (isIntermediate && !isActiveTurn) {
        stack.push({
          kind: 'message',
          id: item.id,
          role: item.role,
          blocks: item.blocks,
          meta: item.meta
        })
        return
      }

      flushStack()
      stackedItems.push({
        kind: 'message',
        id: item.id,
        role: item.role,
        blocks: item.blocks,
        meta: item.meta,
        isIntermediate: isIntermediate && isActiveTurn
      })
    })

    flushStack()

    return stackedItems
  }, [messages, isProcessing])

  const renderBlocks = (blocks: Block[], keyPrefix: string) => {
    return (
      <>
        {blocks.map((block, index) => {
          if (block.type === 'text') {
            return (
              <div
                key={`${keyPrefix}-text-${index}`}
                className="markdown"
                dangerouslySetInnerHTML={renderMarkdown(block.text ?? '')}
              />
            )
          }
          if (block.type === 'attachment') {
            return (
              <div key={`${keyPrefix}-attachment-${index}`} className="block tool-use">
                <div className="block-label">Attachment: {block.name}</div>
                <pre>{block.text}</pre>
              </div>
            )
          }
          if (block.type === 'reasoning') {
            return (
              <div key={`${keyPrefix}-reasoning-${index}`} className="block reasoning">
                <div
                  className="markdown"
                  dangerouslySetInnerHTML={renderMarkdown(block.text ?? '')}
                />
              </div>
            )
          }
          return (
            <div key={`${keyPrefix}-other-${index}`} className="block">
              <div className="block-label">Other</div>
              <pre>{block.text}</pre>
            </div>
          )
        })}
      </>
    )
  }

  const renderMessageBlocks = (item: DisplayItem) => {
    if (item.kind !== 'message') return null
    return renderBlocks(item.blocks, item.id)
  }

  const loginRequired = authMode === 'builtin' && !authAuthorized
  const overlayOpen = drawerOpen || projectPickerOpen
  const showScrollJumps = !overlayOpen && !isAtTop && !isAtBottom

  return (
    <div className="app">
      {loginRequired ? (
        <div className="auth-overlay">
          <div className="auth-modal">
            <div className="auth-title">Unlock console</div>
            <div className="auth-subtitle">This session is protected.</div>
            <form className="auth-form" onSubmit={handleLoginSubmit}>
              <label className="auth-label" htmlFor="auth-password">
                Password
              </label>
              <input
                id="auth-password"
                type="password"
                className="auth-input"
                value={loginPassword}
                onChange={(event) => {
                  setLoginPassword(event.target.value)
                  if (loginError) setLoginError(null)
                }}
                placeholder="Access password"
                autoComplete="current-password"
                autoFocus
                disabled={loginPending}
              />
              {loginError ? <div className="auth-error">{loginError}</div> : null}
              {authSalt ? null : (
                <div className="auth-error">
                  Auth is not configured. Set `CAM_AUTH_MODE=builtin`,
                  `CAM_AUTH_PASSWORD_BCRYPT`, and `CAM_AUTH_SIGNING_SECRET` on the server.
                  See the{' '}
                  <a
                    className="auth-link"
                    href="https://github.com/hive-agents/claude-agent-mobile"
                    target="_blank"
                    rel="noreferrer"
                  >
                    README
                  </a>
                  .
                </div>
              )}
              {authStatusError ? <div className="auth-note">{authStatusError}</div> : null}
              <button type="submit" className="auth-button" disabled={loginPending || !authSalt}>
                {loginPending ? 'Checking...' : 'Unlock'}
              </button>
            </form>
          </div>
        </div>
      ) : null}
      <div
        className={overlayOpen ? 'scrim open' : 'scrim'}
        onClick={() => {
          setDrawerOpen(false)
          setProjectPickerOpen(false)
          setSearchOpen(false)
          setConversationSearchOpen(false)
          setConversationSearchQuery('')
          setModelMenuOpen(false)
        }}
      />
      <aside className={drawerOpen ? 'drawer open' : 'drawer'}>
        <div className="drawer-header">Conversations</div>
        {conversationSearchOpen ? (
          <div className="drawer-search">
            <svg viewBox="0 0 24 24" aria-hidden="true">
              <circle cx="11" cy="11" r="7" fill="none" stroke="currentColor" strokeWidth="2" />
              <line x1="16" y1="16" x2="21" y2="21" stroke="currentColor" strokeWidth="2" />
            </svg>
            <input
              ref={conversationSearchInputRef}
              value={conversationSearchQuery}
              onChange={(event) => setConversationSearchQuery(event.target.value)}
              placeholder="Search conversations"
            />
            {conversationSearchQuery ? (
              <button
                type="button"
                className="icon-button"
                onClick={handleClearConversationSearch}
                aria-label="Clear search"
              >
                x
              </button>
            ) : null}
          </div>
        ) : null}
        <div className="conversation-list">
          {filteredConversations.map((conversation) => (
            <button
              key={conversation.sessionId}
              type="button"
              className={
                activeSessionId === conversation.sessionId
                  ? 'conversation-item active'
                  : 'conversation-item'
              }
              onClick={() => handleSelectConversation(conversation)}
            >
              <div className="conversation-dir">{formatProject(conversation.project)}</div>
              <div className="conversation-preview">
                {truncateWords(conversation.firstPrompt || conversation.project, 12)}
              </div>
            </button>
          ))}
          {filteredConversations.length === 0 ? (
            <div className="conversation-empty">No conversations found.</div>
          ) : null}
        </div>
        <div className="drawer-actions">
          <div className="model-picker">
            <button
              type="button"
              className="model-toggle"
              onClick={() => setModelMenuOpen((prev) => !prev)}
              aria-label={`Model: ${selectedModel}`}
              aria-expanded={modelMenuOpen}
              aria-haspopup="menu"
            >
              {selectedModel === 'opus-4.5' ? (
                <svg viewBox="0 0 24 24" aria-hidden="true">
                  <rect
                    x="5"
                    y="7"
                    width="14"
                    height="12"
                    rx="3"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="2"
                  />
                  <circle cx="9" cy="12" r="1.5" fill="currentColor" />
                  <circle cx="15" cy="12" r="1.5" fill="currentColor" />
                  <line x1="12" y1="3" x2="12" y2="7" stroke="currentColor" strokeWidth="2" />
                  <circle cx="12" cy="3" r="1" fill="currentColor" />
                </svg>
              ) : (
                <svg viewBox="0 0 24 24" aria-hidden="true">
                  <path
                    d="M8.6 6.8C9 5.4 10.3 4.4 11.8 4.4c1.3 0 2.5.7 3.1 1.9 1.5.2 2.7 1.5 2.7 3 0 1-.5 1.9-1.3 2.4.3.5.4 1 .4 1.6 0 1.7-1.4 3.1-3.1 3.1-1 0-1.9-.4-2.5-1.1-.6.7-1.5 1.1-2.5 1.1-1.7 0-3.1-1.4-3.1-3.1 0-1 .5-1.9 1.2-2.4-.3-.4-.5-1-.5-1.6 0-1.4 1-2.7 2.4-2.9Z"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="2"
                    strokeLinejoin="round"
                    strokeLinecap="round"
                  />
                </svg>
              )}
            </button>
            {modelMenuOpen ? (
              <div className="model-menu" role="menu" aria-label="Select model">
                <button
                  type="button"
                  className={selectedModel === 'opus-4.5' ? 'model-option active' : 'model-option'}
                  onClick={() => handleSelectModel('opus-4.5')}
                  role="menuitemradio"
                  aria-checked={selectedModel === 'opus-4.5'}
                >
                  <span className="model-option-icon" aria-hidden="true">
                    <svg viewBox="0 0 24 24">
                      <rect
                        x="5"
                        y="7"
                        width="14"
                        height="12"
                        rx="3"
                        fill="none"
                        stroke="currentColor"
                        strokeWidth="2"
                      />
                      <circle cx="9" cy="12" r="1.5" fill="currentColor" />
                      <circle cx="15" cy="12" r="1.5" fill="currentColor" />
                      <line x1="12" y1="3" x2="12" y2="7" stroke="currentColor" strokeWidth="2" />
                      <circle cx="12" cy="3" r="1" fill="currentColor" />
                    </svg>
                  </span>
                  <span className="model-option-label">opus-4.5</span>
                </button>
                <button
                  type="button"
                  className={selectedModel === 'sonnet-4.5' ? 'model-option active' : 'model-option'}
                  onClick={() => handleSelectModel('sonnet-4.5')}
                  role="menuitemradio"
                  aria-checked={selectedModel === 'sonnet-4.5'}
                >
                  <span className="model-option-icon" aria-hidden="true">
                    <svg viewBox="0 0 24 24">
                      <path
                        d="M8.6 6.8C9 5.4 10.3 4.4 11.8 4.4c1.3 0 2.5.7 3.1 1.9 1.5.2 2.7 1.5 2.7 3 0 1-.5 1.9-1.3 2.4.3.5.4 1 .4 1.6 0 1.7-1.4 3.1-3.1 3.1-1 0-1.9-.4-2.5-1.1-.6.7-1.5 1.1-2.5 1.1-1.7 0-3.1-1.4-3.1-3.1 0-1 .5-1.9 1.2-2.4-.3-.4-.5-1-.5-1.6 0-1.4 1-2.7 2.4-2.9Z"
                        fill="none"
                        stroke="currentColor"
                        strokeWidth="2"
                        strokeLinejoin="round"
                        strokeLinecap="round"
                      />
                    </svg>
                  </span>
                  <span className="model-option-label">sonnet-4.5</span>
                </button>
              </div>
            ) : null}
          </div>
          <button
            type="button"
            className="drawer-search-toggle"
            onClick={handleToggleConversationSearch}
            aria-label="Search conversations"
            aria-pressed={conversationSearchOpen}
          >
            <svg viewBox="0 0 24 24" aria-hidden="true">
              <circle cx="11" cy="11" r="7" fill="none" stroke="currentColor" strokeWidth="2" />
              <line x1="16" y1="16" x2="21" y2="21" stroke="currentColor" strokeWidth="2" />
            </svg>
          </button>
        </div>
      </aside>

      <section className={projectPickerOpen ? 'project-picker open' : 'project-picker'}>
        <div className="project-picker-header">
          <div>
            <div className="project-title">New conversation</div>
            <div className="project-breadcrumbs">
              {dirPath ? (
                <>
                  {breadcrumbs.map((crumb, index) => (
                    <span key={crumb.path} className="crumb">
                      {index > 0 ? <span className="crumb-sep">/</span> : null}
                      <button
                        type="button"
                        className="crumb-button"
                        onClick={() => requestDirList(crumb.path, { resetSearch: true })}
                      >
                        {crumb.label}
                      </button>
                    </span>
                  ))}
                </>
              ) : (
                <span className="project-path">Loading...</span>
              )}
            </div>
          </div>
          <div className="project-header-actions">
            <button
              type="button"
              className="icon-button"
              onClick={handleToggleSearch}
              aria-label="Search folders"
            >
              <svg viewBox="0 0 24 24" aria-hidden="true">
                <circle cx="11" cy="11" r="7" fill="none" stroke="currentColor" strokeWidth="2" />
                <line x1="16" y1="16" x2="21" y2="21" stroke="currentColor" strokeWidth="2" />
              </svg>
            </button>
            <button
              type="button"
              className="icon-button"
              onClick={handleClosePicker}
              aria-label="Close"
            >
              x
            </button>
          </div>
        </div>
        {searchOpen ? (
          <div className="project-search">
            <svg viewBox="0 0 24 24" aria-hidden="true">
              <circle cx="11" cy="11" r="7" fill="none" stroke="currentColor" strokeWidth="2" />
              <line x1="16" y1="16" x2="21" y2="21" stroke="currentColor" strokeWidth="2" />
            </svg>
            <input
              ref={searchInputRef}
              value={searchQuery}
              onChange={(event) => setSearchQuery(event.target.value)}
              placeholder="Search folders"
            />
            {searchQuery ? (
              <button
                type="button"
                className="icon-button"
                onClick={handleClearSearch}
                aria-label="Clear search"
              >
                x
              </button>
            ) : null}
          </div>
        ) : null}
        <div className="project-actions">
          <button
            type="button"
            className="project-action primary"
            onClick={handleUseFolder}
            disabled={!dirPath || dirLoading}
          >
            Use this folder
          </button>
        </div>
        <div className="project-list">
          {dirLoading ? <div className="project-empty">Loading...</div> : null}
          {dirError ? <div className="project-empty">{dirError}</div> : null}
          {!dirLoading && !dirError && filteredDirEntries.length === 0 ? (
            <div className="project-empty">No folders found.</div>
          ) : null}
          {filteredDirEntries.map((entry) => (
            <button
              key={entry}
              type="button"
              className="project-entry"
              onClick={() => handleNavigateDir(entry)}
            >
              <span className="project-entry-name">{entry}</span>
            </button>
          ))}
        </div>
      </section>

      <header className="app-header">
        <button
          type="button"
          className="icon-button hamburger-button"
          onClick={() => setDrawerOpen(true)}
        >
          <span className="hamburger">
            <span />
          </span>
        </button>
        <button type="button" className="icon-button" onClick={handleNewConversation}>
          <span className="new-icon" aria-hidden="true" />
        </button>
      </header>

      <main className="chat-scroll" ref={scrollRef}>
        {currentProject ? (
          <div className="status-pill">{formatProject(currentProject)}</div>
        ) : (
          <div className="status-pill">No project detected</div>
        )}
        {wsStatus !== 'open' ? (
          <div className="status-pill">Server {wsStatus}</div>
        ) : null}
        {displayItems.map((item) => {
          if (item.kind === 'message') {
            const roleClass = item.meta?.isMeta
              ? 'meta'
              : item.role === 'user'
                ? 'user'
                : item.role === 'tool'
                  ? 'tool'
                  : 'assistant'
            const roleLabel =
              item.role === 'user'
                ? 'User'
                : item.role === 'assistant'
                  ? 'Agent'
                  : item.role === 'tool'
                    ? 'Tool'
                    : 'System'
            const showRoleLabel = item.role === 'user' || item.role === 'assistant'
            return (
              <div key={item.id} className="chat-item">
                <div className={`message ${roleClass}${item.isIntermediate ? ' intermediate' : ''}`}>
                  {showRoleLabel ? <div className="message-label">{roleLabel}</div> : null}
                  {renderMessageBlocks(item)}
                </div>
              </div>
            )
          }

          const toolEntries = item.entries.filter((entry) => entry.kind === 'tool')
          const hasStackMessages = item.entries.some((entry) => entry.kind === 'message')
          const canCollapse = toolEntries.length > 1 || hasStackMessages
          const isStackExpanded = !canCollapse || !!expandedStacks[item.id]
          const stackCollapsed = canCollapse && !isStackExpanded
          const entriesToShow = isStackExpanded ? item.entries : toolEntries.slice(0, 1)

          return (
            <div key={item.id} className="chat-item">
              <div className={stackCollapsed ? 'tool-stack stacked' : 'tool-stack'}>
                <div className="tool-stack-header">
                  <div className="tool-stack-title">
                    Tool uses
                    {hasStackMessages ? (
                      <span className="tool-stack-meta">Agent updates</span>
                    ) : null}
                  </div>
                  {canCollapse ? (
                    <button
                      type="button"
                      className="stack-toggle"
                      onClick={() => toggleStack(item.id)}
                    >
                      {isStackExpanded ? 'Collapse stack' : `Stack x${toolEntries.length}`}
                    </button>
                  ) : null}
                </div>
                <div className="tool-stack-list">
                  {entriesToShow.map((entry) => {
                    if (entry.kind === 'message') {
                      return (
                        <div key={entry.id} className="tool-stack-message">
                          <div className="tool-stack-message-label">Agent update</div>
                          {renderBlocks(entry.blocks, `${entry.id}-stack`)}
                        </div>
                      )
                    }
                    const tool = entry.tool
                    const isOpen = !!expandedTools[tool.id]
                    return (
                      <div key={tool.id} className={isOpen ? 'tool-card open' : 'tool-card'}>
                        <button
                          type="button"
                          className="tool-line"
                          onClick={() => toggleTool(tool.id)}
                        >
                          <span className="tool-line-title">Tool use: {tool.name}</span>
                        </button>
                        {isOpen ? (
                          <div className="tool-details">
                            {tool.input ? (
                              <div className="tool-detail">
                                <div className="tool-detail-label">Input</div>
                                <pre>{tool.input}</pre>
                              </div>
                            ) : null}
                            {tool.result ? (
                              <div className="tool-detail">
                                <div className="tool-detail-label">Result</div>
                                <pre>{tool.result}</pre>
                              </div>
                            ) : null}
                          </div>
                        ) : null}
                      </div>
                    )
                  })}
                </div>
              </div>
            </div>
          )
        })}
        {isProcessing ? (
          <div className="chat-item">
            <div className="message assistant">
              <div className="message-label">Agent</div>
              <div className="processing" aria-label="Processing">
                <span>.</span>
                <span>.</span>
                <span>.</span>
              </div>
            </div>
          </div>
        ) : null}
      </main>

      <div className={showScrollJumps ? 'scroll-jumps visible' : 'scroll-jumps'}>
        <button
          type="button"
          className="scroll-jump"
          onClick={scrollToTop}
          aria-label="Go to top"
        >
          <svg viewBox="0 0 24 24" aria-hidden="true">
            <polyline
              points="6 14 12 8 18 14"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
            />
          </svg>
        </button>
        <button
          type="button"
          className="scroll-jump"
          onClick={scrollToBottom}
          aria-label="Go to bottom"
        >
          <svg viewBox="0 0 24 24" aria-hidden="true">
            <polyline
              points="6 10 12 16 18 10"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
            />
          </svg>
        </button>
      </div>

      <footer className="composer">
        {pendingFiles.length > 0 ? (
          <div className="file-list">
            {pendingFiles.map((file) => (
              <div key={file.name} className="file-chip">
                {file.name}
              </div>
            ))}
          </div>
        ) : null}
        <div className="composer-inner">
          <textarea
            placeholder="Send a prompt"
            value={inputText}
            onChange={(event) => setInputText(event.target.value)}
            onKeyDown={handleKeyDown}
          />
          <div className="composer-actions">
            <button
              type="button"
              className={planMode ? 'plan-toggle active' : 'plan-toggle'}
              onClick={() => setPlanMode((prev) => !prev)}
              aria-pressed={planMode}
              aria-label="Toggle plan mode"
            >
              <span className="plan-dot" aria-hidden="true" />
              <span>Plan</span>
            </button>
            <button
              type="button"
              className="file-button"
              onClick={() => fileInputRef.current?.click()}
              aria-label="Attach file"
            >
              +
            </button>
            <button
              type="button"
              className="send-button"
              onClick={sendMessage}
              disabled={!canSend}
              aria-label="Send prompt"
            >
              {'>'}
            </button>
          </div>
        </div>
        <input
          ref={fileInputRef}
          type="file"
          multiple
          hidden
          onChange={handleFileChange}
        />
      </footer>
    </div>
  )
}
