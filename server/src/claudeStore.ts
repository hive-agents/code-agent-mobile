import fs from 'fs/promises'
import { createReadStream, type Dirent, type FSWatcher, watch } from 'fs'
import path from 'path'
import os from 'os'
import crypto from 'crypto'
import readline from 'readline'

export type UIBlock = {
  type: 'text' | 'tool_use' | 'tool_result' | 'reasoning' | 'attachment' | 'other'
  text?: string
  name?: string
  input?: string
}

export type UIMessage = {
  id: string
  role: 'user' | 'assistant' | 'tool' | 'meta'
  blocks: UIBlock[]
  timestamp?: string
  meta?: {
    isMeta?: boolean
    reasoningStatus?: 'provided' | 'disabled' | 'unknown'
  }
}

export type ConversationProvider = 'claude' | 'codex'

export type ConversationSummary = {
  sessionId: string
  project: string
  firstPrompt: string
  updatedAt: number
  provider: ConversationProvider
  model?: string | null
}

export type DirectoryListing = {
  path: string
  parent: string | null
  entries: string[]
}

const CLAUDE_CONFIG_DIR = process.env.CLAUDE_CONFIG_DIR ?? path.join(os.homedir(), '.claude')
const CLAUDE_PROJECTS_DIR = path.join(CLAUDE_CONFIG_DIR, 'projects')
const CODEX_HOME = process.env.CODEX_HOME ?? path.join(os.homedir(), '.codex')
const CODEX_SESSIONS_DIR = path.join(CODEX_HOME, 'sessions')
const ROOT_DIR = path.resolve(process.env.CAM_MOBILE_ROOT ?? os.homedir())
const SHOW_HIDDEN = process.env.CAM_MOBILE_SHOW_HIDDEN === '1'

type CachedConversation = ConversationSummary & {
  filePath: string
  mtimeMs: number
  size: number
  projectDir: string
}

type ConversationListener = (conversations: ConversationSummary[]) => void

const claudeConversationCache = new Map<string, CachedConversation>()
const codexConversationCache = new Map<string, CachedConversation>()
const codexFileIndex = new Map<string, string>()
const claudeProjectWatchers = new Map<string, FSWatcher>()
const codexWatchers = new Map<string, FSWatcher>()
const conversationListeners = new Set<ConversationListener>()
let claudeProjectsWatcher: FSWatcher | null = null
let codexRootWatcher: FSWatcher | null = null
let refreshPromise: Promise<{ conversations: ConversationSummary[]; changed: boolean }> | null = null
let refreshTimer: NodeJS.Timeout | null = null
let lastSnapshotKey = ''
let watchersEnabled = false
const SNAPSHOT_PROMPT_LIMIT = 120

function encodeProjectPath(projectPath: string) {
  return projectPath.replace(/[\\/]/g, '-')
}

async function fileExists(filePath: string) {
  try {
    await fs.access(filePath)
    return true
  } catch {
    return false
  }
}

async function readJsonLines(filePath: string) {
  let content = ''
  try {
    content = await fs.readFile(filePath, 'utf8')
  } catch {
    return []
  }
  return content
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      try {
        return JSON.parse(line)
      } catch {
        return null
      }
    })
    .filter(Boolean)
}

function extractText(content: unknown) {
  if (!content) return ''
  if (typeof content === 'string') return content
  if (Array.isArray(content)) {
    return content
      .filter((block) => block && typeof block === 'object' && (block as any).type === 'text')
      .map((block) => String((block as any).text ?? ''))
      .join('')
  }
  return ''
}

function normalizeClaudeBlocks(content: unknown): UIBlock[] {
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

function extractCodexText(content: unknown) {
  if (!content) return ''
  if (typeof content === 'string') return content
  if (!Array.isArray(content)) return ''
  return content
    .filter((block) => block && typeof block === 'object')
    .map((block) => {
      const type = (block as any).type
      if (type === 'input_text' || type === 'output_text') {
        return String((block as any).text ?? '')
      }
      return ''
    })
    .join('')
}

function isCodexSystemUserText(text: string) {
  const trimmed = text.trim()
  if (!trimmed) return true
  const lower = trimmed.toLowerCase()
  if (lower.startsWith('# agents.md instructions')) return true
  if (lower.includes('<environment_context>')) return true
  if (lower.includes('<instructions>')) return true
  if (lower.includes('<permissions instructions>')) return true
  if (lower.startsWith('interrupted') || lower.includes('the user interrupted')) return true
  if (lower.startsWith('system:')) return true
  return false
}

function filterCodexUserContent(content: unknown) {
  if (typeof content === 'string') {
    return isCodexSystemUserText(content) ? null : content
  }
  if (Array.isArray(content)) {
    const filtered = content.filter((block) => {
      if (!block || typeof block !== 'object') return true
      const type = (block as any).type
      if (type === 'input_text' || type === 'output_text') {
        return !isCodexSystemUserText(String((block as any).text ?? ''))
      }
      return true
    })
    return filtered.length > 0 ? filtered : null
  }
  const text = extractCodexText(content)
  return isCodexSystemUserText(text) ? null : content
}

function normalizeCodexBlocks(content: unknown): UIBlock[] {
  if (!content) return []
  if (typeof content === 'string') return [{ type: 'text', text: content }]
  if (!Array.isArray(content)) return []

  const blocks = content.map((block: any): UIBlock => {
    if (block.type === 'input_text' || block.type === 'output_text') {
      return { type: 'text', text: block.text ?? '' }
    }
    if (block.type === 'image') {
      return { type: 'attachment', name: 'Image', text: block.url ?? 'Image' }
    }
    return { type: 'other', text: JSON.stringify(block ?? {}, null, 2) }
  })

  return blocks.filter((block) => {
    if (block.type === 'text') return Boolean(block.text && block.text.trim())
    if (block.type === 'attachment') return true
    return Boolean(block.text)
  })
}

function buildSnapshotKey(conversations: ConversationSummary[]) {
  return conversations
    .map((conversation) => {
      const promptSnippet = conversation.firstPrompt.slice(0, SNAPSHOT_PROMPT_LIMIT)
      return `${conversation.provider}:${conversation.sessionId}:${conversation.updatedAt}:${conversation.project}:${conversation.model ?? ''}:${promptSnippet}`
    })
    .join('|')
}

async function listClaudeProjectDirectories() {
  let entries: Dirent[] = []
  try {
    entries = await fs.readdir(CLAUDE_PROJECTS_DIR, { withFileTypes: true, encoding: 'utf8' })
  } catch {
    return []
  }

  return entries
    .filter((entry) => entry.isDirectory())
    .map((entry) => ({ name: entry.name, path: path.join(CLAUDE_PROJECTS_DIR, entry.name) }))
}

async function readClaudeSessionMetadata(filePath: string) {
  let project = ''
  let firstPrompt = ''
  let model = ''
  const stream = createReadStream(filePath, { encoding: 'utf8' })
  const rl = readline.createInterface({ input: stream, crlfDelay: Infinity })
  let linesRead = 0

  try {
    for await (const line of rl) {
      const trimmed = line.trim()
      if (!trimmed) continue
      linesRead += 1
      let record: any = null
      try {
        record = JSON.parse(trimmed)
      } catch {
        continue
      }
      if (!project && typeof record?.cwd === 'string') {
        project = record.cwd.trim()
      }
      if (!firstPrompt && record?.type === 'user' && !record?.isMeta) {
        const text = extractText(record.message?.content)
        if (text.trim()) firstPrompt = text.trim()
      }
      if (!model && record?.type === 'assistant' && record?.message?.model) {
        model = String(record.message.model)
      }
      if (project && firstPrompt && model) break
      if (linesRead >= 200) break
    }
  } catch {
  } finally {
    rl.close()
    stream.destroy()
  }

  return { project, firstPrompt, model: model || null }
}

function syncClaudeProjectWatchers(projectDirs: string[]) {
  const next = new Set(projectDirs)
  for (const dir of projectDirs) {
    if (claudeProjectWatchers.has(dir)) continue
    try {
      const watcher = watch(dir, { persistent: false }, () => scheduleConversationRefresh())
      claudeProjectWatchers.set(dir, watcher)
    } catch {
      continue
    }
  }

  for (const [dir, watcher] of claudeProjectWatchers) {
    if (next.has(dir)) continue
    watcher.close()
    claudeProjectWatchers.delete(dir)
  }
}

function ensureClaudeProjectsWatcher() {
  if (claudeProjectsWatcher) return
  try {
    claudeProjectsWatcher = watch(CLAUDE_PROJECTS_DIR, { persistent: false }, () => scheduleConversationRefresh())
  } catch {
    claudeProjectsWatcher = null
  }
}

async function listCodexSessionFiles() {
  const entries: Array<{
    filePath: string
    stats: { mtimeMs: number; size: number }
    projectDir: string
  }> = []
  const watchDirs = new Set<string>()
  watchDirs.add(CODEX_SESSIONS_DIR)

  let years: Dirent[] = []
  try {
    years = await fs.readdir(CODEX_SESSIONS_DIR, { withFileTypes: true, encoding: 'utf8' })
  } catch {
    return { entries, watchDirs: Array.from(watchDirs) }
  }

  const visitDir = async (dir: string, depth: number) => {
    watchDirs.add(dir)
    let items: Dirent[] = []
    try {
      items = await fs.readdir(dir, { withFileTypes: true, encoding: 'utf8' })
    } catch {
      return
    }
    for (const item of items) {
      const fullPath = path.join(dir, item.name)
      if (item.isDirectory() && depth < 3) {
        await visitDir(fullPath, depth + 1)
        continue
      }
      if (!item.isFile()) continue
      if (!item.name.endsWith('.jsonl')) continue
      try {
        const stat = await fs.stat(fullPath)
        entries.push({
          filePath: fullPath,
          stats: { mtimeMs: stat.mtimeMs, size: stat.size },
          projectDir: dir
        })
      } catch {
        continue
      }
    }
  }

  for (const year of years) {
    if (!year.isDirectory()) continue
    const yearPath = path.join(CODEX_SESSIONS_DIR, year.name)
    await visitDir(yearPath, 1)
  }

  return { entries, watchDirs: Array.from(watchDirs) }
}

async function readCodexSessionMetadata(filePath: string) {
  let sessionId = ''
  let project = ''
  let firstPrompt = ''
  let model = ''
  const stream = createReadStream(filePath, { encoding: 'utf8' })
  const rl = readline.createInterface({ input: stream, crlfDelay: Infinity })
  let linesRead = 0

  try {
    for await (const line of rl) {
      const trimmed = line.trim()
      if (!trimmed) continue
      linesRead += 1
      let record: any = null
      try {
        record = JSON.parse(trimmed)
      } catch {
        continue
      }
      if (!sessionId && record?.type === 'session_meta' && record?.payload?.id) {
        sessionId = String(record.payload.id)
        if (!project && typeof record.payload.cwd === 'string') {
          project = record.payload.cwd.trim()
        }
      }
      if (!model && record?.type === 'turn_context' && record?.payload?.model) {
        model = String(record.payload.model)
      }
      if (!firstPrompt && record?.type === 'response_item' && record?.payload?.type === 'message') {
        const payload = record.payload
        if (payload.role === 'user') {
          const content = filterCodexUserContent(payload.content)
          if (!content) continue
          const text = extractCodexText(content)
          if (text.trim()) firstPrompt = text.trim()
        }
      }
      if (sessionId && project && firstPrompt && model) break
      if (linesRead >= 400) break
    }
  } catch {
  } finally {
    rl.close()
    stream.destroy()
  }

  if (!sessionId) {
    const base = path.basename(filePath)
    const match = base.match(/-([0-9a-fA-F-]{8,})\.jsonl$/)
    sessionId = match?.[1] ?? base.replace(/\.jsonl$/, '')
  }

  return { sessionId, project, firstPrompt, model: model || null }
}

function syncCodexWatchers(directories: string[]) {
  const next = new Set(directories)
  for (const dir of directories) {
    if (codexWatchers.has(dir)) continue
    try {
      const watcher = watch(dir, { persistent: false }, () => scheduleConversationRefresh())
      codexWatchers.set(dir, watcher)
    } catch {
      continue
    }
  }

  for (const [dir, watcher] of codexWatchers) {
    if (next.has(dir)) continue
    watcher.close()
    codexWatchers.delete(dir)
  }
}

function stopWatchersIfIdle() {
  if (conversationListeners.size > 0) return
  for (const watcher of claudeProjectWatchers.values()) {
    watcher.close()
  }
  claudeProjectWatchers.clear()
  if (claudeProjectsWatcher) {
    claudeProjectsWatcher.close()
    claudeProjectsWatcher = null
  }
  for (const watcher of codexWatchers.values()) {
    watcher.close()
  }
  codexWatchers.clear()
  if (codexRootWatcher) {
    codexRootWatcher.close()
    codexRootWatcher = null
  }
  watchersEnabled = false
}

function scheduleConversationRefresh() {
  if (!watchersEnabled) return
  if (refreshTimer) clearTimeout(refreshTimer)
  refreshTimer = setTimeout(() => {
    refreshTimer = null
    void emitConversationUpdates()
  }, 150)
}

async function emitConversationUpdates() {
  try {
    const { conversations, changed } = await refreshConversationCache()
    if (!changed) return
    for (const listener of conversationListeners) {
      listener(conversations)
    }
  } catch {
  }
}

async function refreshClaudeCache() {
  const projectDirs = await listClaudeProjectDirectories()
  if (watchersEnabled) {
    ensureClaudeProjectsWatcher()
    syncClaudeProjectWatchers(projectDirs.map((entry) => entry.path))
  }

  const nextCache = new Map<string, CachedConversation>()
  for (const projectDir of projectDirs) {
    let files: Dirent[] = []
    try {
      files = await fs.readdir(projectDir.path, { withFileTypes: true, encoding: 'utf8' })
    } catch {
      continue
    }
    for (const file of files) {
      if (!file.isFile()) continue
      if (!file.name.endsWith('.jsonl')) continue
      const sessionId = file.name.replace(/\.jsonl$/, '')
      const filePath = path.join(projectDir.path, file.name)
      let stats: { mtimeMs: number; size: number }
      try {
        const stat = await fs.stat(filePath)
        stats = { mtimeMs: stat.mtimeMs, size: stat.size }
      } catch {
        continue
      }

      const cached = claudeConversationCache.get(sessionId)
      if (
        cached &&
        cached.filePath === filePath &&
        cached.mtimeMs === stats.mtimeMs &&
        cached.size === stats.size
      ) {
        nextCache.set(sessionId, { ...cached, updatedAt: stats.mtimeMs })
        continue
      }

      const { project, firstPrompt, model } = await readClaudeSessionMetadata(filePath)
      const resolvedProject = project || cached?.project || projectDir.name
      const resolvedPrompt = firstPrompt || cached?.firstPrompt || ''
      const resolvedModel = model ?? cached?.model ?? null
      nextCache.set(sessionId, {
        sessionId,
        project: resolvedProject,
        firstPrompt: resolvedPrompt,
        updatedAt: stats.mtimeMs,
        provider: 'claude',
        model: resolvedModel,
        filePath,
        mtimeMs: stats.mtimeMs,
        size: stats.size,
        projectDir: projectDir.path
      })
    }
  }

  claudeConversationCache.clear()
  for (const [sessionId, entry] of nextCache) {
    claudeConversationCache.set(sessionId, entry)
  }

  return Array.from(nextCache.values()).map(
    ({ filePath, mtimeMs, size, projectDir, ...summary }) => summary
  )
}

async function refreshCodexCache() {
  const { entries, watchDirs } = await listCodexSessionFiles()
  if (watchersEnabled) {
    syncCodexWatchers(watchDirs)
  }

  const nextCache = new Map<string, CachedConversation>()
  const nextIndex = new Map<string, string>()

  for (const entry of entries) {
    const cachedSessionId = codexFileIndex.get(entry.filePath)
    const cached = cachedSessionId ? codexConversationCache.get(cachedSessionId) : undefined
    if (
      cached &&
      cached.filePath === entry.filePath &&
      cached.mtimeMs === entry.stats.mtimeMs &&
      cached.size === entry.stats.size
    ) {
      nextCache.set(cached.sessionId, { ...cached, updatedAt: entry.stats.mtimeMs })
      nextIndex.set(entry.filePath, cached.sessionId)
      continue
    }

    const metadata = await readCodexSessionMetadata(entry.filePath)
    const sessionId = metadata.sessionId || cached?.sessionId || entry.filePath
    const resolvedProject = metadata.project || cached?.project || path.basename(entry.projectDir)
    const resolvedPrompt = metadata.firstPrompt || cached?.firstPrompt || ''
    const resolvedModel = metadata.model ?? cached?.model ?? null

    nextCache.set(sessionId, {
      sessionId,
      project: resolvedProject,
      firstPrompt: resolvedPrompt,
      updatedAt: entry.stats.mtimeMs,
      provider: 'codex',
      model: resolvedModel,
      filePath: entry.filePath,
      mtimeMs: entry.stats.mtimeMs,
      size: entry.stats.size,
      projectDir: entry.projectDir
    })
    nextIndex.set(entry.filePath, sessionId)
  }

  codexConversationCache.clear()
  for (const [sessionId, entry] of nextCache) {
    codexConversationCache.set(sessionId, entry)
  }
  codexFileIndex.clear()
  for (const [filePath, sessionId] of nextIndex) {
    codexFileIndex.set(filePath, sessionId)
  }

  return Array.from(nextCache.values()).map(
    ({ filePath, mtimeMs, size, projectDir, ...summary }) => summary
  )
}

async function refreshConversationCache() {
  if (refreshPromise) return refreshPromise
  refreshPromise = (async () => {
    const [claudeConversations, codexConversations] = await Promise.all([
      refreshClaudeCache(),
      refreshCodexCache()
    ])

    const conversations = [...claudeConversations, ...codexConversations]
    conversations.sort((a, b) => b.updatedAt - a.updatedAt)
    const snapshotKey = buildSnapshotKey(conversations)
    const changed = snapshotKey !== lastSnapshotKey
    lastSnapshotKey = snapshotKey

    return { conversations, changed }
  })().finally(() => {
    refreshPromise = null
  })

  return refreshPromise
}

function clampToRoot(targetPath: string) {
  const resolved = path.resolve(targetPath)
  if (resolved === ROOT_DIR) return resolved
  if (ROOT_DIR === path.parse(ROOT_DIR).root) return resolved
  const rootPrefix = ROOT_DIR.endsWith(path.sep) ? ROOT_DIR : `${ROOT_DIR}${path.sep}`
  return resolved.startsWith(rootPrefix) ? resolved : ROOT_DIR
}

async function resolveClaudeSessionFile(sessionId: string, project?: string) {
  if (project) {
    const candidate = path.join(CLAUDE_PROJECTS_DIR, encodeProjectPath(project), `${sessionId}.jsonl`)
    if (await fileExists(candidate)) return candidate
  }
  const cached = claudeConversationCache.get(sessionId)
  if (cached) return cached.filePath
  const { conversations } = await refreshConversationCache()
  const found = conversations.find(
    (conversation) => conversation.sessionId === sessionId && conversation.provider === 'claude'
  )
  if (!found) return null
  return claudeConversationCache.get(sessionId)?.filePath ?? null
}

async function resolveCodexSessionFile(sessionId: string) {
  const cached = codexConversationCache.get(sessionId)
  if (cached) return cached.filePath
  const { conversations } = await refreshConversationCache()
  const found = conversations.find(
    (conversation) => conversation.sessionId === sessionId && conversation.provider === 'codex'
  )
  if (!found) return null
  return codexConversationCache.get(sessionId)?.filePath ?? null
}

async function resolveSessionFile(sessionId: string, provider?: ConversationProvider, project?: string) {
  if (provider === 'claude') {
    return resolveClaudeSessionFile(sessionId, project)
  }
  if (provider === 'codex') {
    return resolveCodexSessionFile(sessionId)
  }
  const claudeFile = await resolveClaudeSessionFile(sessionId, project)
  if (claudeFile) return claudeFile
  return resolveCodexSessionFile(sessionId)
}

export function watchConversations(listener: ConversationListener) {
  conversationListeners.add(listener)
  watchersEnabled = true
  void refreshConversationCache()
    .then(({ conversations }) => listener(conversations))
    .catch(() => {})
  return () => {
    conversationListeners.delete(listener)
    stopWatchersIfIdle()
  }
}

export async function listConversations() {
  const { conversations } = await refreshConversationCache()
  return conversations
}

export async function listDirectories(requestPath?: string | null): Promise<DirectoryListing> {
  const basePath = requestPath ? clampToRoot(requestPath) : ROOT_DIR
  let dirEntries: string[] = []
  try {
    const entries = await fs.readdir(basePath, { withFileTypes: true, encoding: 'utf8' })
    dirEntries = entries
      .filter((entry) => entry.isDirectory())
      .map((entry) => entry.name)
      .filter((name) => (SHOW_HIDDEN ? true : !name.startsWith('.')))
      .sort((a, b) => a.localeCompare(b))
  } catch {
    dirEntries = []
  }

  const parent = basePath === ROOT_DIR ? null : path.dirname(basePath)

  return {
    path: basePath,
    parent,
    entries: dirEntries
  }
}

export async function createDirectory(parentPath: string | null | undefined, name: string) {
  const basePath = parentPath ? clampToRoot(parentPath) : ROOT_DIR
  const trimmed = name.trim()
  if (!trimmed) {
    throw new Error('Folder name is required.')
  }
  if (trimmed === '.' || trimmed === '..') {
    throw new Error('Folder name is invalid.')
  }
  if (/[\\/]/.test(trimmed)) {
    throw new Error('Folder name cannot include / or \\.')
  }
  if (trimmed.includes('\0')) {
    throw new Error('Folder name is invalid.')
  }

  const nextPath = path.join(basePath, trimmed)
  const resolved = clampToRoot(nextPath)
  if (resolved !== nextPath) {
    throw new Error('Folder name is invalid.')
  }

  try {
    await fs.mkdir(nextPath)
  } catch (error: any) {
    if (error?.code === 'EEXIST') {
      throw new Error('Folder already exists.')
    }
    if (error?.code === 'ENOENT') {
      throw new Error('Parent folder does not exist.')
    }
    throw new Error('Unable to create folder.')
  }

  return { path: nextPath }
}

async function loadClaudeConversation(sessionId: string, project?: string) {
  const filePath = await resolveSessionFile(sessionId, 'claude', project)
  if (!filePath) return { messages: [] as UIMessage[], model: null, provider: 'claude' as const }

  const records = await readJsonLines(filePath)
  const messages: UIMessage[] = []
  let lastModel: string | null = null

  for (const record of records) {
    if (record?.type !== 'user' && record?.type !== 'assistant') continue
    const message = record.message
    if (!message || !message.role) continue

    if (message.role === 'assistant' && message.model) {
      lastModel = message.model
    }

    const blocks = normalizeClaudeBlocks(message.content)
    if (blocks.length === 0) continue

    const reasoningStatus = blocks.some((block) => block.type === 'reasoning')
      ? 'provided'
      : record.thinkingMetadata?.disabled
        ? 'disabled'
        : 'unknown'

    const role = record.isMeta
      ? 'meta'
      : blocks.every((block) => block.type === 'tool_result')
        ? 'tool'
        : (message.role as 'user' | 'assistant')

    messages.push({
      id: record.uuid ?? message.id ?? crypto.randomUUID(),
      role,
      blocks,
      timestamp: record.timestamp,
      meta: {
        isMeta: record.isMeta ?? false,
        reasoningStatus: message.role === 'assistant' ? reasoningStatus : undefined
      }
    })
  }

  return { messages, model: lastModel, provider: 'claude' as const }
}

async function loadCodexConversation(sessionId: string) {
  const filePath = await resolveSessionFile(sessionId, 'codex')
  if (!filePath) return { messages: [] as UIMessage[], model: null, provider: 'codex' as const }

  const records = await readJsonLines(filePath)
  const messages: UIMessage[] = []
  let lastModel: string | null = null

  for (const record of records) {
    if (record?.type === 'turn_context' && record?.payload?.model) {
      lastModel = String(record.payload.model)
    }

    if (record?.type === 'response_item' && record?.payload?.type === 'message') {
      const payload = record.payload
      if (payload.role !== 'user' && payload.role !== 'assistant') continue
      const content =
        payload.role === 'user' ? filterCodexUserContent(payload.content) : payload.content
      if (payload.role === 'user' && !content) continue
      const blocks = normalizeCodexBlocks(content)
      if (blocks.length === 0) continue
      messages.push({
        id: payload.id ?? crypto.randomUUID(),
        role: payload.role,
        blocks,
        timestamp: record.timestamp
      })
      continue
    }

    if (record?.type === 'response_item' && record?.payload?.type === 'function_call') {
      const payload = record.payload
      const toolId = payload.call_id ?? crypto.randomUUID()
      let input = ''
      if (payload.arguments !== undefined) {
        if (typeof payload.arguments === 'string') {
          try {
            input = JSON.stringify(JSON.parse(payload.arguments), null, 2)
          } catch {
            input = payload.arguments
          }
        } else {
          input = JSON.stringify(payload.arguments, null, 2)
        }
      }
      messages.push({
        id: `${toolId}-call`,
        role: 'assistant',
        blocks: [
          {
            type: 'tool_use',
            name: payload.name ?? 'tool',
            input: input || undefined
          }
        ],
        timestamp: record.timestamp
      })
      continue
    }

    if (record?.type === 'response_item' && record?.payload?.type === 'function_call_output') {
      const payload = record.payload
      const toolId = payload.call_id ?? crypto.randomUUID()
      const output =
        typeof payload.output === 'string' ? payload.output : JSON.stringify(payload.output ?? {}, null, 2)
      messages.push({
        id: `${toolId}-result`,
        role: 'assistant',
        blocks: [{ type: 'tool_result', text: output }],
        timestamp: record.timestamp
      })
    }
  }

  return { messages, model: lastModel, provider: 'codex' as const }
}

export async function loadConversation(
  sessionId: string,
  provider?: ConversationProvider,
  project?: string
) {
  if (provider === 'claude') {
    return loadClaudeConversation(sessionId, project)
  }
  if (provider === 'codex') {
    return loadCodexConversation(sessionId)
  }
  const claudeFile = await resolveSessionFile(sessionId, 'claude', project)
  if (claudeFile) {
    return loadClaudeConversation(sessionId, project)
  }
  return loadCodexConversation(sessionId)
}

export async function getBootstrapState() {
  const conversations = await listConversations()
  const activeConversation = conversations[0] ?? null
  const activeConversationId = activeConversation?.sessionId ?? null
  const currentProject = activeConversation?.project ?? null
  const { messages, model, provider } = activeConversationId
    ? await loadConversation(activeConversationId, activeConversation?.provider, activeConversation?.project ?? undefined)
    : { messages: [], model: null, provider: null }

  return {
    currentProject,
    conversations,
    activeConversationId,
    messages,
    model,
    provider
  }
}
