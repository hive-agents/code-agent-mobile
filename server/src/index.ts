import { WebSocketServer, type RawData, type WebSocket } from 'ws'
import crypto from 'crypto'
import http, { type IncomingMessage } from 'http'
import { query, type PermissionMode, type SDKMessage } from '@anthropic-ai/claude-agent-sdk'
import {
  getBootstrapState,
  listConversations,
  loadConversation,
  listDirectories,
  watchConversations,
  type UIBlock,
  type UIMessage
} from './claudeStore.js'

type Attachment = {
  name: string
  content: string
}

type ClientMessage =
  | { type: 'init' }
  | { type: 'select_conversation'; sessionId: string; project?: string }
  | { type: 'new_conversation'; project?: string }
  | { type: 'list_dirs'; path?: string | null }
  | { type: 'send_prompt'; text: string; attachments?: Attachment[]; model?: string; planMode?: boolean }

const PORT = Number(process.env.CAM_MOBILE_PORT ?? process.env.PORT ?? 8787)
const WS_PATH = process.env.CAM_MOBILE_WS_PATH ?? '/cam-ws'
const SONNET_MODEL = process.env.CLAUDE_SONNET_MODEL ?? 'claude-sonnet-4-5-20250929'
const OPUS_MODEL = process.env.CLAUDE_OPUS_MODEL ?? 'claude-opus-4-5-20251101'
const DEFAULT_MODEL =
  process.env.CLAUDE_MODEL ?? process.env.ANTHROPIC_MODEL ?? SONNET_MODEL

const AUTH_MODE = (process.env.CAM_AUTH_MODE ?? 'builtin').toLowerCase()
const AUTH_COOKIE_NAME = process.env.CAM_AUTH_COOKIE_NAME ?? 'cam_session'
const AUTH_LOGIN_PATH = process.env.CAM_AUTH_LOGIN_PATH ?? '/cam-login'
const AUTH_LOGOUT_PATH = process.env.CAM_AUTH_LOGOUT_PATH ?? '/cam-logout'
const AUTH_STATUS_PATH = process.env.CAM_AUTH_STATUS_PATH ?? '/cam-auth/status'
const AUTH_PASSWORD_HASH = (process.env.CAM_AUTH_PASSWORD_BCRYPT ?? '').trim()
const AUTH_SIGNING_SECRET = (process.env.CAM_AUTH_SIGNING_SECRET ?? '').trim()
const AUTH_EXTERNAL_SIGNING_SECRET = process.env.CAM_AUTH_EXTERNAL_SIGNING_SECRET ?? ''
const AUTH_COOKIE_TTL_SECONDS = Number(process.env.CAM_AUTH_COOKIE_TTL_SECONDS ?? 60 * 60 * 24 * 30)
const AUTH_COOKIE_SECURE = (process.env.CAM_AUTH_COOKIE_SECURE ?? 'false').toLowerCase() === 'true'
const AUTH_CORS_ORIGIN = process.env.CAM_AUTH_CORS_ORIGIN ?? ''

const wss = new WebSocketServer({ noServer: true })

function base64UrlEncode(value: string | Buffer) {
  const buffer = typeof value === 'string' ? Buffer.from(value, 'utf8') : value
  return buffer
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '')
}

function base64UrlDecode(value: string) {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/').padEnd(value.length + ((4 - (value.length % 4)) % 4), '=')
  return Buffer.from(padded, 'base64').toString('utf8')
}

function parseCookies(header: string | undefined) {
  if (!header) return {} as Record<string, string>
  return header.split(';').reduce<Record<string, string>>((acc, part) => {
    const [rawKey, ...rest] = part.trim().split('=')
    if (!rawKey) return acc
    acc[rawKey] = decodeURIComponent(rest.join('='))
    return acc
  }, {})
}

function signToken(payloadBase64: string, secret: string) {
  const signature = crypto.createHmac('sha256', secret).update(payloadBase64).digest()
  return `${payloadBase64}.${base64UrlEncode(signature)}`
}

function createSessionToken() {
  const now = Math.floor(Date.now() / 1000)
  const payload = {
    iat: now,
    exp: now + AUTH_COOKIE_TTL_SECONDS
  }
  const payloadBase64 = base64UrlEncode(JSON.stringify(payload))
  return signToken(payloadBase64, AUTH_SIGNING_SECRET)
}

function verifySignedToken(token: string, secret: string) {
  const [payloadBase64, signature] = token.split('.')
  if (!payloadBase64 || !signature) return false
  const expected = signToken(payloadBase64, secret).split('.')[1]
  const signatureBuf = Buffer.from(signature)
  const expectedBuf = Buffer.from(expected)
  if (signatureBuf.length !== expectedBuf.length) return false
  if (!crypto.timingSafeEqual(signatureBuf, expectedBuf)) return false
  try {
    const payload = JSON.parse(base64UrlDecode(payloadBase64)) as { exp?: number }
    if (payload.exp && Date.now() / 1000 > payload.exp) return false
    return true
  } catch {
    return false
  }
}

function isAuthorized(req: IncomingMessage) {
  if (AUTH_MODE === 'off') return true
  const cookies = parseCookies(req.headers.cookie)
  const token = cookies[AUTH_COOKIE_NAME]
  if (!token) return false
  if (AUTH_MODE === 'external') {
    if (AUTH_EXTERNAL_SIGNING_SECRET) {
      return verifySignedToken(token, AUTH_EXTERNAL_SIGNING_SECRET)
    }
    return true
  }
  if (AUTH_MODE === 'builtin') {
    if (!AUTH_SIGNING_SECRET) return false
    return verifySignedToken(token, AUTH_SIGNING_SECRET)
  }
  return false
}

function setCorsHeaders(req: http.IncomingMessage, res: http.ServerResponse) {
  if (!AUTH_CORS_ORIGIN) return
  const origin = req.headers.origin
  if (!origin) return
  if (AUTH_CORS_ORIGIN === '*' || AUTH_CORS_ORIGIN.split(',').map((item) => item.trim()).includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin)
    res.setHeader('Access-Control-Allow-Credentials', 'true')
    res.setHeader('Vary', 'Origin')
  }
}

function setAuthCookie(res: http.ServerResponse, token: string | null) {
  const parts = [
    `${AUTH_COOKIE_NAME}=${token ? encodeURIComponent(token) : ''}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    token ? `Max-Age=${AUTH_COOKIE_TTL_SECONDS}` : 'Max-Age=0'
  ]
  if (AUTH_COOKIE_SECURE) parts.push('Secure')
  res.setHeader('Set-Cookie', parts.join('; '))
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`)
  if (req.method === 'OPTIONS') {
    setCorsHeaders(req, res)
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS')
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type')
    res.writeHead(204)
    res.end()
    return
  }

  if (url.pathname === AUTH_LOGIN_PATH && req.method === 'POST') {
    if (AUTH_MODE !== 'builtin') {
      res.writeHead(404)
      res.end('Not found')
      return
    }
    if (!AUTH_PASSWORD_HASH || !AUTH_SIGNING_SECRET) {
      setCorsHeaders(req, res)
      res.writeHead(500)
      res.end('Server auth is not configured.')
      return
    }
    let body = ''
    req.on('data', (chunk) => {
      body += chunk
      if (body.length > 10_000) req.destroy()
    })
    req.on('end', () => {
      let hash = ''
      try {
        const parsed = JSON.parse(body || '{}') as { hash?: string }
        hash = parsed.hash ?? ''
      } catch {
        setCorsHeaders(req, res)
        res.writeHead(400)
        res.end('Malformed request.')
        return
      }
      if (!hash) {
        setCorsHeaders(req, res)
        res.writeHead(400)
        res.end('Missing hash.')
        return
      }
      const normalizedHash = hash.trim()
      const hashBuf = Buffer.from(normalizedHash)
      const expectedBuf = Buffer.from(AUTH_PASSWORD_HASH)
      if (hashBuf.length !== expectedBuf.length) {
        setCorsHeaders(req, res)
        res.writeHead(401)
        res.end('Unauthorized')
        return
      }
      if (!crypto.timingSafeEqual(hashBuf, expectedBuf)) {
        setCorsHeaders(req, res)
        res.writeHead(401)
        res.end('Unauthorized')
        return
      }
      const token = createSessionToken()
      setAuthCookie(res, token)
      setCorsHeaders(req, res)
      res.writeHead(200)
      res.end('ok')
    })
    return
  }

  if (url.pathname === AUTH_LOGOUT_PATH && req.method === 'POST') {
    setAuthCookie(res, null)
    setCorsHeaders(req, res)
    res.writeHead(200)
    res.end('ok')
    return
  }

  if (url.pathname === AUTH_STATUS_PATH && req.method === 'GET') {
    const authorized = isAuthorized(req)
    setCorsHeaders(req, res)
    res.setHeader('Content-Type', 'application/json')
    res.writeHead(200)
    res.end(
      JSON.stringify({
        mode: AUTH_MODE,
        authorized,
        loginPath: AUTH_LOGIN_PATH,
        logoutPath: AUTH_LOGOUT_PATH,
        salt: AUTH_MODE === 'builtin' ? AUTH_PASSWORD_HASH : null
      })
    )
    return
  }

  res.writeHead(404)
  res.end('Not found')
})

server.on('upgrade', (req, socket, head) => {
  const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`)
  if (url.pathname !== WS_PATH) {
    socket.destroy()
    return
  }
  if (!isAuthorized(req)) {
    socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n')
    socket.destroy()
    return
  }
  wss.handleUpgrade(req, socket, head, (ws) => {
    wss.emit('connection', ws, req)
  })
})

function normalizeBlocks(content: unknown): UIBlock[] {
  if (!content) return []
  if (typeof content === 'string') return [{ type: 'text', text: content }]
  if (!Array.isArray(content)) return []

  return content.map((block: any) => {
    if (block.type === 'text') {
      return { type: 'text', text: block.text ?? '' }
    }
    if (block.type === 'tool_use') {
      return {
        type: 'tool_use',
        name: block.name ?? 'tool',
        input: JSON.stringify(block.input ?? {}, null, 2)
      }
    }
    if (block.type === 'tool_result') {
      return {
        type: 'tool_result',
        text: typeof block.content === 'string' ? block.content : JSON.stringify(block.content ?? {}, null, 2)
      }
    }
    if (block.type === 'thinking' || block.type === 'analysis' || block.type === 'reasoning') {
      return { type: 'reasoning', text: block.text ?? '' }
    }
    return { type: 'other', text: JSON.stringify(block ?? {}, null, 2) }
  })
}

function sdkMessageToUI(message: SDKMessage): UIMessage | null {
  if (message.type !== 'assistant') return null
  const blocks = normalizeBlocks(message.message.content)
  if (blocks.length === 0) return null

  const reasoningStatus = blocks.some((block) => block.type === 'reasoning') ? 'provided' : 'unknown'

  return {
    id: message.message.id ?? crypto.randomUUID(),
    role: 'assistant',
    blocks,
    meta: {
      reasoningStatus
    }
  }
}

function buildPrompt(text: string, attachments: Attachment[]) {
  const trimmed = text.trim()
  if (attachments.length === 0) return trimmed

  const header = trimmed.length ? trimmed : 'See attached files.'
  const parts = attachments
    .map((file) => `--- ${file.name} ---\n${file.content}`)
    .join('\n\n')
  return `${header}\n\nAttachments:\n${parts}`
}

function buildUserMessage(text: string, attachments: Attachment[]): UIMessage {
  const blocks: UIBlock[] = []
  if (text.trim()) {
    blocks.push({ type: 'text', text: text.trim() })
  }
  for (const file of attachments) {
    blocks.push({
      type: 'attachment',
      name: file.name,
      text: `${file.name} (${file.content.length.toLocaleString()} chars)`
    })
  }

  if (blocks.length === 0) {
    blocks.push({ type: 'text', text: 'Sent attachments.' })
  }

  return {
    id: crypto.randomUUID(),
    role: 'user',
    blocks
  }
}

function resolveModel(model?: string | null) {
  if (!model) return null
  const trimmed = model.trim()
  if (!trimmed) return null
  const normalized = trimmed.toLowerCase()
  if (normalized === 'sonnet-4.5') return SONNET_MODEL
  if (normalized === 'opus-4.5') return OPUS_MODEL
  return trimmed
}

function resolveModelLabel(model?: string | null) {
  if (!model) return null
  const normalized = model.trim().toLowerCase()
  const opusMatch = OPUS_MODEL.toLowerCase()
  const sonnetMatch = SONNET_MODEL.toLowerCase()
  if (normalized === opusMatch || normalized.includes('opus')) return 'opus-4.5'
  if (normalized === sonnetMatch || normalized.includes('sonnet')) return 'sonnet-4.5'
  return null
}

wss.on('connection', (socket: WebSocket) => {
  let activeSessionId: string | null = null
  let activeProject: string | null = null
  let activeModel = DEFAULT_MODEL
  let isStreaming = false

  const send = (payload: unknown) => {
    socket.send(JSON.stringify(payload))
  }

  const unsubscribeConversations = watchConversations((conversations) => {
    send({ type: 'conversations', conversations })
  })

  const resolveQueryCwd = () => {
    const candidate = activeProject?.trim()
    return candidate && candidate.length > 0 ? candidate : process.cwd()
  }

  socket.on('message', async (data: RawData) => {
    let parsed: ClientMessage | null = null
    try {
      const text = typeof data === 'string' ? data : data.toString()
      parsed = JSON.parse(text)
    } catch {
      send({ type: 'error', error: 'Malformed message received from client.' })
      return
    }

    if (!parsed) return

    if (parsed.type === 'init') {
      const state = await getBootstrapState()
      activeSessionId = state.activeConversationId
      activeProject = state.currentProject
      if (state.model) activeModel = state.model
      const modelLabel = resolveModelLabel(state.model ?? activeModel)
      send({
        type: 'bootstrap',
        currentProject: state.currentProject,
        conversations: state.conversations,
        activeConversationId: state.activeConversationId,
        messages: state.messages,
        model: modelLabel
      })
      return
    }

    if (parsed.type === 'select_conversation') {
      activeSessionId = parsed.sessionId
      activeProject = parsed.project ?? activeProject
      const { messages, model } = await loadConversation(parsed.sessionId, parsed.project)
      if (model) activeModel = model
      const modelLabel = resolveModelLabel(model ?? activeModel)
      send({
        type: 'conversation',
        sessionId: parsed.sessionId,
        messages,
        currentProject: activeProject,
        model: modelLabel
      })
      return
    }

    if (parsed.type === 'new_conversation') {
      activeSessionId = null
      if (parsed.project) activeProject = parsed.project
      send({ type: 'conversation', sessionId: null, messages: [], currentProject: activeProject })
      return
    }

    if (parsed.type === 'list_dirs') {
      const listing = await listDirectories(parsed.path)
      send({ type: 'dir_list', ...listing })
      return
    }

    if (parsed.type === 'send_prompt') {
      if (isStreaming) {
        send({ type: 'error', error: 'A response is already streaming.' })
        return
      }
      const attachments = parsed.attachments ?? []
      const prompt = buildPrompt(parsed.text ?? '', attachments)
      if (!prompt.trim()) return
      const requestedModel = resolveModel(parsed.model)
      if (requestedModel) {
        activeModel = requestedModel
      }

      isStreaming = true
      send({ type: 'processing', active: true })
      send({ type: 'message', message: buildUserMessage(parsed.text ?? '', attachments) })

      try {
        const permissionMode: PermissionMode = parsed.planMode ? 'plan' : 'default'
        const options = {
          model: requestedModel ?? activeModel,
          permissionMode,
          cwd: resolveQueryCwd(),
          ...(activeSessionId ? { resume: activeSessionId } : {})
        }
        for await (const msg of query({ prompt, options })) {
          if (msg.session_id) activeSessionId = msg.session_id
          const uiMessage = sdkMessageToUI(msg)
          if (uiMessage) send({ type: 'message', message: uiMessage })
        }
        const conversations = await listConversations()
        send({ type: 'conversations', conversations })
      } catch (error) {
        send({ type: 'error', error: 'Failed to send prompt to Claude.' })
      } finally {
        isStreaming = false
        send({ type: 'processing', active: false })
      }
    }
  })

  socket.on('close', () => {
    unsubscribeConversations()
  })
})

server.listen(PORT, () => {
  console.log(`claude-agent-mobile server listening on ws://localhost:${PORT}${WS_PATH}`)
  console.log(`auth mode: ${AUTH_MODE}`)
})
