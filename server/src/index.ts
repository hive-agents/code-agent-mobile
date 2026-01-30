import { WebSocketServer, type RawData, type WebSocket } from 'ws'
import crypto from 'crypto'
import fs from 'fs/promises'
import http, { type IncomingMessage, type ServerResponse } from 'http'
import https from 'https'
import os from 'os'
import path from 'path'
import type { Duplex } from 'stream'
import { query, type Query, type PermissionMode, type PermissionResult, type PermissionUpdate, type SDKMessage, type SDKUserMessage } from '@anthropic-ai/claude-agent-sdk'
import { Codex, type ThreadItem } from '@openai/codex-sdk'
import {
  getBootstrapState,
  listConversations,
  loadConversation,
  listDirectories,
  createDirectory,
  watchConversations,
  type ConversationSummary,
  type ConversationProvider,
  type UIBlock,
  type UIMessage
} from './claudeStore.js'

type TextAttachment = { type: 'text'; name: string; content: string }
type ImageAttachment = { type: 'image'; name: string; mediaType: string; data: string }
type Attachment = TextAttachment | ImageAttachment
type QuestionPrompt = {
  question: string
  header: string
  options: Array<{ label: string; description: string }>
  multiSelect: boolean
}

type PendingPermission = {
  requestId: string
  resolve: (result: PermissionResult) => void
  toolName: string
  toolUseID: string
  toolInput: Record<string, unknown>
  blockedPath?: string
  decisionReason?: string
  suggestions?: PermissionUpdate[]
}

type PendingQuestion = {
  requestId: string
  resolve: (answers: Record<string, string>) => void
  toolUseId: string
  questions: QuestionPrompt[]
}

type PendingExitPlan = {
  requestId: string
  resolve: (choice: 'auto' | 'manual' | 'deny') => void
  toolUseId: string
  input: Record<string, unknown>
}

type ClientMessage =
  | { type: 'init' }
  | { type: 'select_conversation'; sessionId: string; project?: string; provider?: ConversationProvider }
  | { type: 'new_conversation'; project?: string }
  | { type: 'list_dirs'; path?: string | null }
  | { type: 'create_dir'; parent?: string | null; name: string }
  | { type: 'send_prompt'; text: string; attachments?: Attachment[]; model?: string; planMode?: boolean }
  | { type: 'permission_response'; requestId: string; allow: boolean; allowForSession?: boolean; suggestions?: PermissionUpdate[] }
  | { type: 'question_response'; requestId: string; answers: Record<string, string> }
  | { type: 'exit_plan_response'; requestId: string; choice: 'auto' | 'manual' | 'deny' }

const PORT = Number(process.env.CAM_MOBILE_PORT ?? process.env.PORT ?? 8787)
const WS_PATH = process.env.CAM_MOBILE_WS_PATH ?? '/cam-ws'
const SONNET_MODEL = process.env.CLAUDE_SONNET_MODEL ?? 'claude-sonnet-4-5-20250929'
const OPUS_MODEL = process.env.CLAUDE_OPUS_MODEL ?? 'claude-opus-4-5-20251101'
const DEFAULT_MODEL =
  process.env.CLAUDE_MODEL ?? process.env.ANTHROPIC_MODEL ?? SONNET_MODEL
const codex = new Codex()

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
const AUTH_EXTERNAL_VERIFY_URL = process.env.CAM_AUTH_EXTERNAL_VERIFY_URL ?? ''
const AUTH_EXTERNAL_VERIFY_TIMEOUT_MS = Number(process.env.CAM_AUTH_EXTERNAL_VERIFY_TIMEOUT_MS ?? 5000)

const wss = new WebSocketServer({ noServer: true })
const pendingPermissions = new Map<string, PendingPermission>()
const pendingQuestions = new Map<string, PendingQuestion>()
const pendingExitPlans = new Map<string, PendingExitPlan>()

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

function authCookieHeader(token: string) {
  return `${AUTH_COOKIE_NAME}=${encodeURIComponent(token)}`
}

function verifyExternalSession(token: string) {
  if (!AUTH_EXTERNAL_VERIFY_URL) return Promise.resolve(false)
  let url: URL
  try {
    url = new URL(AUTH_EXTERNAL_VERIFY_URL)
  } catch {
    return Promise.resolve(false)
  }
  const client = url.protocol === 'https:' ? https : http
  const port = url.port ? Number(url.port) : url.protocol === 'https:' ? 443 : 80
  const path = `${url.pathname}${url.search}`

  return new Promise<boolean>((resolve) => {
    const req = client.request(
      {
        method: 'GET',
        hostname: url.hostname,
        port,
        path,
        headers: {
          Accept: 'application/json',
          Cookie: authCookieHeader(token)
        },
        timeout: AUTH_EXTERNAL_VERIFY_TIMEOUT_MS
      },
      (res) => {
        res.resume()
        resolve(res.statusCode === 200)
      }
    )
    req.on('timeout', () => {
      req.destroy()
      resolve(false)
    })
    req.on('error', () => resolve(false))
    req.end()
  })
}

async function isAuthorized(req: IncomingMessage) {
  if (AUTH_MODE === 'off') return true
  const cookies = parseCookies(req.headers.cookie)
  const token = cookies[AUTH_COOKIE_NAME]
  if (!token) return false
  if (AUTH_MODE === 'external') {
    if (AUTH_EXTERNAL_SIGNING_SECRET && !verifySignedToken(token, AUTH_EXTERNAL_SIGNING_SECRET)) {
      return false
    }
    return verifyExternalSession(token)
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

async function handleAuthStatus(req: IncomingMessage, res: ServerResponse) {
  const authorized = await isAuthorized(req)
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
}

async function handleUpgrade(req: IncomingMessage, socket: Duplex, head: Buffer) {
  const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`)
  if (url.pathname !== WS_PATH) {
    socket.destroy()
    return
  }
  if (!(await isAuthorized(req))) {
    socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n')
    socket.destroy()
    return
  }
  wss.handleUpgrade(req, socket, head, (ws) => {
    wss.emit('connection', ws, req)
  })
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
    void handleAuthStatus(req, res)
    return
  }

  res.writeHead(404)
  res.end('Not found')
})

server.on('upgrade', (req, socket, head) => {
  void handleUpgrade(req, socket, head)
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

function codexItemToMessages(item: ThreadItem): UIMessage[] {
  const now = new Date().toISOString()
  if (item.type === 'agent_message') {
    return [
      {
        id: item.id ?? crypto.randomUUID(),
        role: 'assistant',
        blocks: [{ type: 'text', text: item.text ?? '' }],
        timestamp: now
      }
    ]
  }
  if (item.type === 'reasoning') {
    return [
      {
        id: item.id ?? crypto.randomUUID(),
        role: 'assistant',
        blocks: [{ type: 'reasoning', text: item.text ?? '' }],
        timestamp: now,
        meta: { reasoningStatus: 'provided' }
      }
    ]
  }
  if (item.type === 'command_execution') {
    const input = JSON.stringify({ command: item.command }, null, 2)
    const resultLines = []
    resultLines.push(`status: ${item.status}`)
    if (item.exit_code !== undefined) {
      resultLines.push(`exit_code: ${item.exit_code}`)
    }
    if (item.aggregated_output) {
      resultLines.push('', item.aggregated_output)
    }
    return [
      {
        id: item.id ?? crypto.randomUUID(),
        role: 'assistant',
        blocks: [
          { type: 'tool_use', name: 'shell_command', input },
          { type: 'tool_result', text: resultLines.join('\n') }
        ],
        timestamp: now
      }
    ]
  }
  if (item.type === 'mcp_tool_call') {
    const input = JSON.stringify(item.arguments ?? {}, null, 2)
    let output = ''
    if (item.result?.structured_content !== undefined) {
      output = JSON.stringify(item.result.structured_content, null, 2)
    } else if (item.result?.content) {
      output = JSON.stringify(item.result.content, null, 2)
    } else if (item.error?.message) {
      output = item.error.message
    }
    return [
      {
        id: item.id ?? crypto.randomUUID(),
        role: 'assistant',
        blocks: [
          { type: 'tool_use', name: item.tool ?? 'mcp_tool', input },
          { type: 'tool_result', text: output }
        ],
        timestamp: now
      }
    ]
  }
  if (item.type === 'file_change') {
    const input = JSON.stringify(item.changes ?? [], null, 2)
    const output = `status: ${item.status}`
    return [
      {
        id: item.id ?? crypto.randomUUID(),
        role: 'assistant',
        blocks: [
          { type: 'tool_use', name: 'file_change', input },
          { type: 'tool_result', text: output }
        ],
        timestamp: now
      }
    ]
  }
  if (item.type === 'web_search') {
    const input = JSON.stringify({ query: item.query }, null, 2)
    return [
      {
        id: item.id ?? crypto.randomUUID(),
        role: 'assistant',
        blocks: [{ type: 'tool_use', name: 'web_search', input }],
        timestamp: now
      }
    ]
  }
  if (item.type === 'error') {
    return [
      {
        id: item.id ?? crypto.randomUUID(),
        role: 'assistant',
        blocks: [{ type: 'other', text: item.message ?? 'Error' }],
        timestamp: now
      }
    ]
  }
  return []
}

function buildPrompt(text: string, attachments: Attachment[]) {
  const trimmed = text.trim()
  const textAttachments = attachments.filter((a): a is TextAttachment => a.type === 'text')
  if (textAttachments.length === 0) return trimmed

  const header = trimmed.length ? trimmed : 'See attached files.'
  const parts = textAttachments
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
      text: file.type === 'image'
        ? `Image: ${file.name}`
        : `${file.name} (${file.content.length.toLocaleString()} chars)`
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

function mediaTypeExtension(mediaType: string) {
  const normalized = mediaType.toLowerCase()
  if (normalized.includes('png')) return '.png'
  if (normalized.includes('jpeg') || normalized.includes('jpg')) return '.jpg'
  if (normalized.includes('webp')) return '.webp'
  if (normalized.includes('gif')) return '.gif'
  return ''
}

async function writeCodexImages(attachments: ImageAttachment[]) {
  if (attachments.length === 0) {
    return { paths: [] as string[], cleanup: async () => {} }
  }

  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'cam-codex-'))
  const paths: string[] = []
  try {
    for (const image of attachments) {
      const ext = mediaTypeExtension(image.mediaType)
      const filename = `image-${crypto.randomUUID()}${ext}`
      const filePath = path.join(tempDir, filename)
      await fs.writeFile(filePath, Buffer.from(image.data, 'base64'))
      paths.push(filePath)
    }
  } catch (error) {
    await fs.rm(tempDir, { recursive: true, force: true })
    throw error
  }

  return {
    paths,
    cleanup: async () => {
      await fs.rm(tempDir, { recursive: true, force: true })
    }
  }
}

async function isGitRepository(startPath: string) {
  let current = path.resolve(startPath)
  while (true) {
    const candidate = path.join(current, '.git')
    try {
      const stat = await fs.stat(candidate)
      if (stat.isDirectory() || stat.isFile()) return true
    } catch {
    }
    const parent = path.dirname(current)
    if (parent === current) break
    current = parent
  }
  return false
}

function buildExitPlanResult(choice: 'auto' | 'manual' | 'deny') {
  if (choice === 'auto') {
    return 'User approved the plan and wants edits auto-accepted.'
  }
  if (choice === 'manual') {
    return 'User approved the plan but wants to manually approve edits.'
  }
  return 'User declined to exit plan mode.'
}

function resolveModel(model?: string | null) {
  if (!model) return null
  const trimmed = model.trim()
  if (!trimmed) return null
  const normalized = trimmed.toLowerCase()
  if (normalized === 'sonnet-4.5') return SONNET_MODEL
  if (normalized === 'opus-4.5') return OPUS_MODEL
  if (normalized === 'gpt-5.2-codex') return 'gpt-5.2-codex'
  return trimmed
}

function resolveModelLabel(model?: string | null) {
  if (!model) return null
  const normalized = model.trim().toLowerCase()
  const opusMatch = OPUS_MODEL.toLowerCase()
  const sonnetMatch = SONNET_MODEL.toLowerCase()
  if (normalized.includes('gpt-5.2-codex') || normalized.includes('codex')) return 'gpt-5.2-codex'
  if (normalized === opusMatch || normalized.includes('opus')) return 'opus-4.5'
  if (normalized === sonnetMatch || normalized.includes('sonnet')) return 'sonnet-4.5'
  return null
}

function resolveProviderForModel(model?: string | null): ConversationProvider | null {
  if (!model) return null
  const normalized = model.trim().toLowerCase()
  if (!normalized) return null
  if (normalized.includes('gpt-5.2-codex') || normalized.includes('codex')) {
    return 'codex'
  }
  return 'claude'
}

function sendPendingRequests(send: (payload: unknown) => void) {
  for (const pending of pendingPermissions.values()) {
    send({
      type: 'permission_request',
      requestId: pending.requestId,
      toolName: pending.toolName,
      toolInput: pending.toolInput,
      blockedPath: pending.blockedPath,
      decisionReason: pending.decisionReason,
      toolUseID: pending.toolUseID,
      suggestions: pending.suggestions
    })
  }
  for (const pending of pendingQuestions.values()) {
    send({
      type: 'user_question',
      requestId: pending.requestId,
      toolUseId: pending.toolUseId,
      questions: pending.questions
    })
  }
  for (const pending of pendingExitPlans.values()) {
    send({
      type: 'exit_plan_request',
      requestId: pending.requestId,
      toolUseId: pending.toolUseId,
      input: pending.input
    })
  }
}

wss.on('connection', (socket: WebSocket) => {
  let activeSessionId: string | null = null
  let activeProject: string | null = null
  let activeModel = DEFAULT_MODEL
  let activeProvider: ConversationProvider | null = resolveProviderForModel(activeModel)
  let isStreaming = false
  let activeQuery: Query | null = null
  let lastConversationSummaries: ConversationSummary[] = []
  let activeConversationUpdatedAt: number | null = null
  let lastMessageCount = 0
  let syncInFlight = false
  let forceNewConversation = false

  const send = (payload: unknown) => {
    socket.send(JSON.stringify(payload))
  }

  const syncActiveConversationFromDisk = async (conversations: ConversationSummary[]) => {
    if (!activeSessionId) return
    const summary = conversations.find((conversation) => conversation.sessionId === activeSessionId)
    if (!summary) return
    if (activeConversationUpdatedAt !== null && summary.updatedAt <= activeConversationUpdatedAt) {
      return
    }
    if (syncInFlight) return
    syncInFlight = true
    try {
      const project = summary.project || activeProject || undefined
      const { messages, model, provider } = await loadConversation(activeSessionId, summary.provider, project)
      if (messages.length > lastMessageCount) {
        const nextMessages = messages.slice(lastMessageCount)
        lastMessageCount = messages.length
        for (const message of nextMessages) {
          send({ type: 'message', message })
        }
      }
      if (model) {
        activeModel = model
      }
      if (provider) {
        activeProvider = provider
      }
      activeConversationUpdatedAt = summary.updatedAt
    } finally {
      syncInFlight = false
    }
  }

  const unsubscribeConversations = watchConversations((conversations) => {
    lastConversationSummaries = conversations
    const formatted = conversations.map((conversation) => ({
      ...conversation,
      model: resolveModelLabel(conversation.model ?? null)
    }))
    send({ type: 'conversations', conversations: formatted })
    void syncActiveConversationFromDisk(conversations)
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
      activeProvider = state.provider ?? resolveProviderForModel(activeModel)
      lastConversationSummaries = state.conversations
      activeConversationUpdatedAt = state.activeConversationId
        ? state.conversations.find((conversation) => conversation.sessionId === state.activeConversationId)?.updatedAt ?? null
        : null
      lastMessageCount = state.messages.length
      const modelLabel = resolveModelLabel(state.model ?? activeModel)
      const formattedConversations = state.conversations.map((conversation) => ({
        ...conversation,
        model: resolveModelLabel(conversation.model ?? null)
      }))
      send({
        type: 'bootstrap',
        currentProject: state.currentProject,
        conversations: formattedConversations,
        activeConversationId: state.activeConversationId,
        messages: state.messages,
        model: modelLabel,
        provider: state.provider ?? activeProvider
      })
      sendPendingRequests(send)
      forceNewConversation = false
      return
    }

    if (parsed.type === 'select_conversation') {
      activeSessionId = parsed.sessionId
      const summary = lastConversationSummaries.find(
        (conversation) =>
          conversation.sessionId === parsed.sessionId &&
          (!parsed.provider || conversation.provider === parsed.provider)
      )
      activeProject = parsed.project ?? summary?.project ?? activeProject
      const provider = parsed.provider ?? summary?.provider ?? activeProvider ?? 'claude'
      const { messages, model } = await loadConversation(parsed.sessionId, provider, activeProject ?? undefined)
      if (model) activeModel = model
      activeProvider = provider
      lastMessageCount = messages.length
      activeConversationUpdatedAt = summary?.updatedAt ?? null
      const modelLabel = resolveModelLabel(model ?? activeModel)
      send({
        type: 'conversation',
        sessionId: parsed.sessionId,
        messages,
        currentProject: activeProject,
        model: modelLabel,
        provider: activeProvider
      })
      forceNewConversation = false
      return
    }

    if (parsed.type === 'new_conversation') {
      activeSessionId = null
      if (parsed.project) activeProject = parsed.project
      activeProvider = null
      lastMessageCount = 0
      activeConversationUpdatedAt = null
      forceNewConversation = true
      send({ type: 'conversation', sessionId: null, messages: [], currentProject: activeProject })
      return
    }

    if (parsed.type === 'list_dirs') {
      const listing = await listDirectories(parsed.path)
      send({ type: 'dir_list', ...listing })
      return
    }

    if (parsed.type === 'create_dir') {
      try {
        const created = await createDirectory(parsed.parent ?? null, parsed.name)
        send({ type: 'dir_created', path: created.path })
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Unable to create folder.'
        send({ type: 'dir_error', error: message })
      }
      return
    }

    if (parsed.type === 'permission_response') {
      const pending = pendingPermissions.get(parsed.requestId)
      if (pending) {
        pendingPermissions.delete(parsed.requestId)
        // Note: SDK automatically adds toolUseID to the response, so we don't include it here
        const result: PermissionResult = parsed.allow
          ? {
              behavior: 'allow',
              updatedInput: pending.toolInput,
              updatedPermissions: parsed.allowForSession ? parsed.suggestions : undefined
            }
          : { behavior: 'deny', message: 'User denied permission' }
        console.log('[permission_response] allow:', parsed.allow, 'allowForSession:', parsed.allowForSession)
        console.log('[permission_response] suggestions:', JSON.stringify(parsed.suggestions, null, 2))
        console.log('[permission_response] result:', JSON.stringify(result, null, 2))
        pending.resolve(result)
      }
      return
    }

    if (parsed.type === 'question_response') {
      const pending = pendingQuestions.get(parsed.requestId)
      if (pending) {
        pendingQuestions.delete(parsed.requestId)
        pending.resolve(parsed.answers)
      }
      return
    }

    if (parsed.type === 'exit_plan_response') {
      const pending = pendingExitPlans.get(parsed.requestId)
      if (pending) {
        pendingExitPlans.delete(parsed.requestId)
        pending.resolve(parsed.choice)
      }
      return
    }

    if (parsed.type === 'send_prompt') {
      if (isStreaming) {
        send({ type: 'error', error: 'A response is already streaming.' })
        return
      }
      const attachments = parsed.attachments ?? []
      const textPrompt = buildPrompt(parsed.text ?? '', attachments)

      const requestedModel = resolveModel(parsed.model)
      const provider =
        resolveProviderForModel(requestedModel ?? activeModel) ?? activeProvider ?? 'claude'

      if (activeSessionId && activeProvider && provider !== activeProvider) {
        send({ type: 'error', error: 'Cannot change model providers mid-conversation.' })
        return
      }

      if (requestedModel) {
        activeModel = requestedModel
      }
      if (!activeProvider) {
        activeProvider = provider
      }

      const hasImages = attachments.some((a) => a.type === 'image')
      if (!textPrompt.trim() && !hasImages) {
        return
      }

      isStreaming = true
      send({ type: 'processing', active: true })
      send({ type: 'message', message: buildUserMessage(parsed.text ?? '', attachments) })
      lastMessageCount += 1

      try {
        if (provider === 'codex') {
          if (!activeSessionId && !forceNewConversation) {
            const resumeProject = activeProject ?? resolveQueryCwd()
            const latestCodex = lastConversationSummaries
              .filter((conversation) => conversation.provider === 'codex')
              .filter((conversation) => conversation.project === resumeProject)
              .sort((a, b) => b.updatedAt - a.updatedAt)[0]
            if (latestCodex) {
              activeSessionId = latestCodex.sessionId
              activeProvider = 'codex'
            }
          }
          const imageAttachments = attachments.filter((att): att is ImageAttachment => att.type === 'image')
          const cwd = resolveQueryCwd()
          if (!(await isGitRepository(cwd))) {
            send({
              type: 'warning',
              message: 'Codex is running outside a git repo (skipGitRepoCheck enabled).'
            })
          }
          const { paths, cleanup } = await writeCodexImages(imageAttachments)
          try {
            const input: Array<{ type: 'text'; text: string } | { type: 'local_image'; path: string }> = []
            if (textPrompt.trim()) {
              input.push({ type: 'text', text: textPrompt })
            }
            for (const imagePath of paths) {
              input.push({ type: 'local_image', path: imagePath })
            }
            const threadOptions = {
              model: requestedModel ?? activeModel,
              workingDirectory: cwd,
              skipGitRepoCheck: true,
              approvalPolicy: 'never' as const
            }
            const thread = activeSessionId
              ? codex.resumeThread(activeSessionId, threadOptions)
              : codex.startThread(threadOptions)
            const { events } = await thread.runStreamed(input)

            for await (const event of events) {
              if (event.type === 'thread.started') {
                if (event.thread_id && event.thread_id !== activeSessionId) {
                  activeSessionId = event.thread_id
                  activeConversationUpdatedAt = null
                  activeProvider = 'codex'
                }
                forceNewConversation = false
                continue
              }
              if (event.type === 'turn.failed') {
                send({ type: 'error', error: event.error.message ?? 'Codex turn failed.' })
                break
              }
              if (event.type === 'error') {
                send({ type: 'error', error: event.message ?? 'Codex stream failed.' })
                break
              }
              if (event.type === 'item.completed') {
                const messages = codexItemToMessages(event.item)
                for (const message of messages) {
                  send({ type: 'message', message })
                  lastMessageCount += 1
                }
              }
            }
          } finally {
            await cleanup()
          }
        } else {
          // Build content blocks for Claude API
          const contentBlocks: Array<
            | { type: 'text'; text: string }
            | { type: 'image'; source: { type: 'base64'; media_type: string; data: string } }
          > = []

          // Add image blocks first (Claude prefers images before text)
          for (const att of attachments) {
            if (att.type === 'image') {
              contentBlocks.push({
                type: 'image',
                source: {
                  type: 'base64',
                  media_type: att.mediaType,
                  data: att.data
                }
              })
            }
          }

          // Add text prompt (with text attachments embedded)
          if (textPrompt.trim()) {
            contentBlocks.push({ type: 'text', text: textPrompt })
          }

          // If no content, skip
          if (contentBlocks.length === 0) return

          const permissionMode: PermissionMode = parsed.planMode ? 'plan' : 'default'
          const options = {
            model: requestedModel ?? activeModel,
            permissionMode,
            cwd: resolveQueryCwd(),
            ...(activeSessionId ? { resume: activeSessionId } : {}),
            canUseTool: async (
              toolName: string,
              input: Record<string, unknown>,
              { signal, blockedPath, decisionReason, toolUseID, suggestions }: {
                signal: AbortSignal
                blockedPath?: string
                decisionReason?: string
                toolUseID: string
                suggestions?: PermissionUpdate[]
              }
            ): Promise<PermissionResult> => {
              const requestId = crypto.randomUUID()

              console.log('[canUseTool] toolName:', toolName)
              console.log('[canUseTool] toolUseID:', toolUseID)
              console.log('[canUseTool] suggestions:', JSON.stringify(suggestions, null, 2))

              send({
                type: 'permission_request',
                requestId,
                toolName,
                toolInput: input,
                blockedPath,
                decisionReason,
                toolUseID,
                suggestions
              })

              return new Promise<PermissionResult>((resolve) => {
                pendingPermissions.set(requestId, {
                  requestId,
                  resolve,
                  toolName,
                  toolUseID,
                  toolInput: input,
                  blockedPath,
                  decisionReason,
                  suggestions
                })

                signal.addEventListener('abort', () => {
                  pendingPermissions.delete(requestId)
                  // Note: SDK automatically adds toolUseID to the response
                  resolve({ behavior: 'deny', message: 'Request cancelled' })
                })
              })
            }
          }

          // Use SDKUserMessage for multimodal content (images), string for text-only
          const prompt = hasImages
            ? (async function* () {
                yield {
                  type: 'user',
                  message: { role: 'user', content: contentBlocks },
                  parent_tool_use_id: null,
                  session_id: activeSessionId ?? ''
                } as SDKUserMessage
              })()
            : textPrompt

          const queryResult = query({ prompt, options })
          activeQuery = queryResult

          for await (const msg of queryResult) {
            if (msg.session_id && msg.session_id !== activeSessionId) {
              activeSessionId = msg.session_id
              activeConversationUpdatedAt = null
              activeProvider = 'claude'
            }

            // Check if this is an AskUserQuestion tool_use
            if (msg.type === 'assistant' && msg.message.content) {
              for (const block of msg.message.content) {
                if (block.type === 'tool_use' && block.name === 'ExitPlanMode') {
                  const requestId = crypto.randomUUID()

                  send({
                    type: 'exit_plan_request',
                    requestId,
                    toolUseId: block.id,
                    input: block.input ?? {}
                  })

                  const choice = await new Promise<'auto' | 'manual' | 'deny'>((resolve) => {
                    pendingExitPlans.set(requestId, {
                      requestId,
                      resolve,
                      toolUseId: block.id,
                      input: (block.input ?? {}) as Record<string, unknown>
                    })
                  })

                  await activeQuery?.streamInput((async function* () {
                    yield {
                      type: 'user',
                      message: {
                        role: 'user',
                        content: [{
                          type: 'tool_result',
                          tool_use_id: block.id,
                          content: buildExitPlanResult(choice)
                        }]
                      },
                      parent_tool_use_id: null,
                      session_id: activeSessionId ?? ''
                    } as SDKUserMessage
                  })())
                }

                if (block.type === 'tool_use' && block.name === 'AskUserQuestion') {
                  const requestId = crypto.randomUUID()
                  const input = block.input as { questions: QuestionPrompt[] }

                  // Send question to frontend
                  send({
                    type: 'user_question',
                    requestId,
                    toolUseId: block.id,
                    questions: input.questions
                  })

                  // Wait for user response
                  const answers = await new Promise<Record<string, string>>((resolve) => {
                    pendingQuestions.set(requestId, {
                      requestId,
                      resolve,
                      toolUseId: block.id,
                      questions: input.questions
                    })
                  })

                  // Stream the tool_result back to SDK
                  await activeQuery?.streamInput((async function* () {
                    yield {
                      type: 'user',
                      message: {
                        role: 'user',
                        content: [{
                          type: 'tool_result',
                          tool_use_id: block.id,
                          content: JSON.stringify({ answers })
                        }]
                      },
                      parent_tool_use_id: null,
                      session_id: activeSessionId ?? ''
                    } as SDKUserMessage
                  })())
                }
              }
            }

            const uiMessage = sdkMessageToUI(msg)
            if (uiMessage) {
              send({ type: 'message', message: uiMessage })
              lastMessageCount += 1
            }
          }
        }
        const conversations = await listConversations()
        const formatted = conversations.map((conversation) => ({
          ...conversation,
          model: resolveModelLabel(conversation.model ?? null)
        }))
        send({ type: 'conversations', conversations: formatted })
      } catch (error) {
        const label = provider === 'codex' ? 'Codex' : 'Claude'
        send({ type: 'error', error: `Failed to send prompt to ${label}.` })
      } finally {
        isStreaming = false
        activeQuery = null
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
