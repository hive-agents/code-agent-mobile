import { WebSocketServer, type RawData, type WebSocket } from 'ws'
import crypto from 'crypto'
import { query, type SDKMessage } from '@anthropic-ai/claude-agent-sdk'
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
  | { type: 'send_prompt'; text: string; attachments?: Attachment[] }

const PORT = Number(process.env.CC_MOBILE_PORT ?? process.env.PORT ?? 8787)
const DEFAULT_MODEL =
  process.env.CLAUDE_MODEL ?? process.env.ANTHROPIC_MODEL ?? 'claude-sonnet-4-5-20250929'

const wss = new WebSocketServer({ port: PORT })

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
      send({
        type: 'bootstrap',
        currentProject: state.currentProject,
        conversations: state.conversations,
        activeConversationId: state.activeConversationId,
        messages: state.messages
      })
      return
    }

    if (parsed.type === 'select_conversation') {
      activeSessionId = parsed.sessionId
      activeProject = parsed.project ?? activeProject
      const { messages, model } = await loadConversation(parsed.sessionId, parsed.project)
      if (model) activeModel = model
      send({
        type: 'conversation',
        sessionId: parsed.sessionId,
        messages,
        currentProject: activeProject
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

      isStreaming = true
      send({ type: 'processing', active: true })
      send({ type: 'message', message: buildUserMessage(parsed.text ?? '', attachments) })

      try {
        const options = {
          model: activeModel,
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

console.log(`claude-agent-mobile server listening on ws://localhost:${PORT}`)
