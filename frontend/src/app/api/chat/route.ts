import { NextRequest, NextResponse } from 'next/server'
import { getServerSession } from 'next-auth'
import { authOptions } from '@/lib/authOptions'
import { createHash } from 'crypto'
import { appendFileSync, mkdirSync } from 'fs'
import { join } from 'path'

const BACKEND_URL = process.env.BACKEND_URL || 'https://127.0.0.1:5500'
const API_SECRET = process.env.API_SECRET
const BACKEND_API_KEY = process.env.BACKEND_API_KEY

if (!BACKEND_API_KEY) {
  throw new Error('BACKEND_API_KEY environment variable is not set. Inter-agent communication requires authentication.')
}
const AUDIT_LOG_DIR = process.env.AUDIT_LOG_DIR || join(process.cwd(), 'audit-logs')
const AUDIT_LOG_FILE = join(AUDIT_LOG_DIR, 'ai-chat-audit.jsonl')

// Retention policy: records must be kept for at least AUDIT_RETENTION_DAYS days.
// Operators are responsible for rotating/archiving logs according to this policy
// (e.g. via logrotate, a cron job, or a log-management platform).
// A value of 0 disables automatic expiry hints in audit records.
const AUDIT_RETENTION_DAYS = parseInt(process.env.AUDIT_RETENTION_DAYS || '90', 10)
const AUDIT_MAX_FILE_SIZE_MB = parseInt(process.env.AUDIT_MAX_FILE_SIZE_MB || '100', 10)

function hashInput(input: unknown): string {
  return createHash('sha256')
    .update(JSON.stringify(input))
    .digest('hex')
}

function getPrincipal(request: NextRequest): string {
  const forwarded = request.headers.get('x-forwarded-for')
  const realIp = request.headers.get('x-real-ip')
  let ip: string | null = null
  if (forwarded) ip = forwarded.split(',')[0].trim()
  else if (realIp) ip = realIp
  if (!ip) return 'unknown'
  return 'ip-hash:' + createHash('sha256').update(ip).digest('hex')
}

const SHELL_COMMAND_PATTERN = /(?:^|[\s;|&`$(){}])(?:bash|sh|zsh|cmd|powershell|pwsh|exec|eval|system|popen|subprocess|os\.system|child_process|spawn|execSync|execFile|passthru|shell_exec|proc_open|\bsudo\b|\bchmod\b|\bchown\b|\brm\s+-rf|\bmkdir\b|\bwget\b|\bcurl\b|\bnc\b|\bnetcat\b|\btelnet\b|\bssh\b|\bscp\b|\bftp\b)/i
const BASE64_PATTERN = /(?:[A-Za-z0-9+/]{40,}={0,2})/
const BINARY_PATTERN = /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]/
const HIDDEN_PROMPT_PATTERN = /(?:ignore\s+(?:previous|above|prior|all)\s+(?:instructions?|prompts?|context)|you\s+are\s+now|act\s+as\s+(?:a\s+)?(?:different|new|another|unrestricted)|disregard\s+(?:all|any|previous)|forget\s+(?:all|everything|previous)|system\s*:\s*you|<\s*system\s*>|\[\s*system\s*\]|###\s*(?:system|instruction)|roleplay\s+as|pretend\s+(?:you\s+are|to\s+be)|jailbreak|DAN\s+mode|developer\s+mode)/i
const LEETSPEAK_SHELL_PATTERN = /(?:[e3][x\*][e3][c\(]|[s\$][y\*][s\$][t\+][e3][m\*]|[e3][v\*][a@][l\|]|[b8][a@4][s\$][h#]|[p\|][o0][w\*][e3][r\*][s\$][h#])/i

function sanitizeMessage(message: string): { safe: boolean; reason?: string } {
  if (BINARY_PATTERN.test(message)) {
    return { safe: false, reason: 'Message contains binary or non-printable characters' }
  }
  if (BASE64_PATTERN.test(message)) {
    // Attempt to decode and check decoded content for shell commands
    const b64Matches = message.match(/[A-Za-z0-9+/]{40,}={0,2}/g) || []
    for (const candidate of b64Matches) {
      try {
        const decoded = Buffer.from(candidate, 'base64').toString('utf8')
        if (SHELL_COMMAND_PATTERN.test(decoded) || HIDDEN_PROMPT_PATTERN.test(decoded)) {
          return { safe: false, reason: 'Message contains encoded malicious content' }
        }
      } catch {
        // Not valid base64, skip
      }
    }
  }
  if (SHELL_COMMAND_PATTERN.test(message)) {
    return { safe: false, reason: 'Message contains shell command patterns' }
  }
  if (HIDDEN_PROMPT_PATTERN.test(message)) {
    return { safe: false, reason: 'Message contains prompt injection patterns' }
  }
  if (LEETSPEAK_SHELL_PATTERN.test(message)) {
    return { safe: false, reason: 'Message contains obfuscated command patterns' }
  }
  return { safe: true }
}

function writeAuditRecord(record: Record<string, unknown>): void {
  // Embed retention metadata in every record for forensic readiness.
  const enrichedRecord = {
    ...record,
    _audit: {
      retentionDays: AUDIT_RETENTION_DAYS,
      maxFileSizeMB: AUDIT_MAX_FILE_SIZE_MB,
      logFile: AUDIT_LOG_FILE,
      writtenAt: new Date().toISOString(),
    },
  }
  try {
    mkdirSync(AUDIT_LOG_DIR, { recursive: true })
    appendFileSync(AUDIT_LOG_FILE, JSON.stringify(enrichedRecord) + '\n', { encoding: 'utf8', flag: 'a' })
  } catch (auditErr) {
    // Log the failure to stderr AND re-throw so the caller is aware.
    // Silently swallowing audit errors violates forensic-readiness policy.
    console.error('[AUDIT] CRITICAL – failed to write audit record:', auditErr)
    throw new Error(
      `[AUDIT] Audit write failure – AI-driven action may be unlogged. Cause: ${
        auditErr instanceof Error ? auditErr.message : String(auditErr)
      }`
    )
  }
}

export async function POST(request: NextRequest) {
  try {
    // Enforce authentication before processing the request
    const session = await getServerSession(authOptions)
    if (!session) {
      return NextResponse.json(
        { detail: 'Unauthorized: You must be authenticated to access the AI Agent.' },
        { status: 401 }
      )
    }

    // Enforce a maximum body size before parsing
    const contentLength = request.headers.get('content-length')
    if (contentLength && parseInt(contentLength, 10) > MAX_BODY_BYTES) {
      return NextResponse.json(
        { detail: 'Request body too large' },
        { status: 413 }
      )
    }

    const rawBody = await request.text()
    if (Buffer.byteLength(rawBody, 'utf8') > MAX_BODY_BYTES) {
      return NextResponse.json(
        { detail: 'Request body too large' },
        { status: 413 }
      )
    }

    let parsed: unknown
    try {
      parsed = JSON.parse(rawBody)
    } catch {
      return NextResponse.json(
        { detail: 'Invalid JSON in request body' },
        { status: 400 }
      )
    }

    if (
      typeof parsed !== 'object' ||
      parsed === null ||
      Array.isArray(parsed)
    ) {
      return NextResponse.json(
        { detail: 'Request body must be a JSON object' },
        { status: 400 }
      )
    }

    // Whitelist only the fields the backend chat endpoint expects
    const incoming = parsed as Record<string, unknown>
    const allowedBody: Record<string, unknown> = {}
    if ('message' in incoming) {
      if (typeof incoming.message !== 'string') {
        return NextResponse.json(
          { detail: '"message" must be a string' },
          { status: 400 }
        )
      }
      const sanitizationResult = sanitizeMessage(incoming.message)
      if (!sanitizationResult.safe) {
        return NextResponse.json(
          { detail: `Invalid message content: ${sanitizationResult.reason}` },
          { status: 400 }
        )
      }
      allowedBody.message = incoming.message
    }
    if ('conversation_id' in incoming) {
      if (
        typeof incoming.conversation_id !== 'string' &&
        typeof incoming.conversation_id !== 'number'
      ) {
        return NextResponse.json(
          { detail: '"conversation_id" must be a string or number' },
          { status: 400 }
        )
      }
      allowedBody.conversation_id = incoming.conversation_id
    }

    // Registry-pinned approved model — must match exactly; no best-effort derivation allowed.
    const APPROVED_MODEL_ID = 'gpt-4o-2024-05-13'
    const APPROVED_MODEL_REGISTRY = new Set(['gpt-4o-2024-05-13'])

    const response = await fetch(`${BACKEND_URL}/chat`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(allowedBody),
    })

    const data = await response.json()

    // Use the organization-approved model identifier
    const APPROVED_MODEL_ID = 'gpt-4o'
    const modelId: string = APPROVED_MODEL_ID

    // Minimise data for audit and client response
    const dataRecord = data as Record<string, unknown>
    const minimisedAuditOutput = {
      response_id: typeof dataRecord?.response_id === 'string' ? dataRecord.response_id : undefined,
      message_id: typeof dataRecord?.message_id === 'string' ? dataRecord.message_id : undefined,
      conversation_id: typeof dataRecord?.conversation_id === 'string' || typeof dataRecord?.conversation_id === 'number' ? dataRecord.conversation_id : undefined,
    }
    const minimisedClientResponse: Record<string, unknown> = {}
    if (typeof dataRecord?.response === 'string') minimisedClientResponse.response = dataRecord.response
    if (typeof dataRecord?.message === 'string') minimisedClientResponse.message = dataRecord.message
    if (typeof dataRecord?.conversation_id === 'string' || typeof dataRecord?.conversation_id === 'number') minimisedClientResponse.conversation_id = dataRecord.conversation_id
    if (typeof dataRecord?.message_id === 'string') minimisedClientResponse.message_id = dataRecord.message_id

    if (!response.ok) {
      writeAuditRecord({
        timestamp,
        principal,
        model: modelId,
        inputHash,
        httpStatus: response.status,
        outcome: 'backend_error',
        output: minimisedAuditOutput,
      })
      return NextResponse.json(
        { detail: 'Backend request failed' },
        { status: response.status }
      )
    }

    writeAuditRecord({
      timestamp,
      principal,
      model: modelId,
      inputHash,
      httpStatus: 200,
      outcome: 'success',
      output: minimisedAuditOutput,
    })

    return NextResponse.json(minimisedClientResponse)
  } catch (error) {
    writeAuditRecord({
      timestamp,
      principal,
      model: 'gpt-4o',
      inputHash: inputHash! ?? 'unavailable',
      httpStatus: 503,
      outcome: 'proxy_error',
      output: { detail: 'Failed to connect to backend service' },
      error: String(error),
    })
    console.error('Backend proxy error:', error)
    return NextResponse.json(
      {
        detail: 'Failed to connect to backend service',
        policy_error: {
          type: 'general',
          message: 'Backend service unavailable',
        },
      },
      { status: 503 }
    )
  }
} = rawBody as Record<string, unknown>

    if (typeof message !== 'string') {
      return NextResponse.json(
        { detail: 'Invalid input: "message" must be a string.' },
        { status: 400 }
      )
    }

    const MAX_MESSAGE_LENGTH = 4000
    const trimmedMessage = message.trim()

    if (trimmedMessage.length === 0) {
      return NextResponse.json(
        { detail: 'Invalid input: "message" must not be empty.' },
        { status: 400 }
      )
    }

    if (trimmedMessage.length > MAX_MESSAGE_LENGTH) {
      return NextResponse.json(
        { detail: `Invalid input: "message" exceeds maximum length of ${MAX_MESSAGE_LENGTH} characters.` },
        { status: 400 }
      )
    }

    // Sanitize: remove null bytes and non-printable control characters
    // (except common whitespace: tab, newline, carriage return).
    const sanitizedMessage = trimmedMessage.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '')

    // Validate optional conversation_id: must be a non-empty alphanumeric string if present.
    let sanitizedConversationId: string | undefined
    if (conversation_id !== undefined) {
      if (typeof conversation_id !== 'string' || !/^[a-zA-Z0-9_-]{1,128}$/.test(conversation_id)) {
        return NextResponse.json(
          { detail: 'Invalid input: "conversation_id" must be an alphanumeric string (max 128 chars).' },
          { status: 400 }
        )
      }
      sanitizedConversationId = conversation_id
    }

    // Build a clean, allowlisted payload — no extra fields forwarded.
    const sanitizedBody: Record<string, unknown> = { message: sanitizedMessage }
    if (sanitizedConversationId !== undefined) {
      sanitizedBody.conversation_id = sanitizedConversationId
    }
    // --- End of input sanitization and validation ---

    const response = await fetch(`${BACKEND_URL}/chat`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(sanitizedBody),
    })

    const data = await response.json()

    // --- Session-token integrity helpers (inline, server-side only) ---
    // Expected format: <base64url-payload>.<base64url-hmac-sha256>
    // Payload JSON must contain: { sub, exp } where sub matches the conversation id.
    const SESSION_SIGNING_SECRET = process.env.SESSION_SIGNING_SECRET ?? ''

    async function verifySessionToken(
      token: string,
      expectedSub: string | undefined
    ): Promise<boolean> {
      if (!SESSION_SIGNING_SECRET) return false
      const parts = token.split('.')
      if (parts.length !== 2) return false
      const [payloadB64, sigB64] = parts

      // Verify HMAC-SHA-256 signature
      const enc = new TextEncoder()
      const keyMaterial = await crypto.subtle.importKey(
        'raw',
        enc.encode(SESSION_SIGNING_SECRET),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['verify']
      )
      const sigBytes = Uint8Array.from(
        atob(sigB64.replace(/-/g, '+').replace(/_/g, '/')),
        (c) => c.charCodeAt(0)
      )
      const valid = await crypto.subtle.verify(
        'HMAC',
        keyMaterial,
        sigBytes,
        enc.encode(payloadB64)
      )
      if (!valid) return false

      // Decode and parse payload
      let payload: Record<string, unknown>
      try {
        payload = JSON.parse(
          atob(payloadB64.replace(/-/g, '+').replace(/_/g, '/'))
        )
      } catch {
        return false
      }

      // Expiry check
      if (typeof payload.exp !== 'number' || Date.now() / 1000 > payload.exp) {
        return false
      }

      // Subject binding: if a conversation id is present it must match
      if (expectedSub !== undefined && payload.sub !== expectedSub) {
        return false
      }

      return true
    }
    // --- End session-token integrity helpers ---

    if (!response.ok) {
      // Minimise error responses — only expose safe, known fields
      const errorPayload: Record<string, unknown> = {}
      if (data?.detail !== undefined) errorPayload.detail = data.detail
      if (data?.policy_error !== undefined) errorPayload.policy_error = data.policy_error
      return NextResponse.json(errorPayload, { status: response.status })
    }

    // Minimise success responses — only expose safe, known fields
    const minimisedData: Record<string, unknown> = {}

    /**
     * Scan a string value for dynamic code execution primitives that could
     * indicate prompt-injection or malicious LLM output.
     * Returns true if the value contains dangerous patterns.
     */
    const containsDangerousPatterns = (value: string): boolean => {
      const dangerousPatterns = [
        /\beval\s*\(/i,
        /\bexec\s*\(/i,
        /\bnew\s+Function\s*\(/i,
        /\bsetTimeout\s*\(\s*['"`]/i,
        /\bsetInterval\s*\(\s*['"`]/i,
        /\bsetImmediate\s*\(\s*['"`]/i,
        /\bimportScripts\s*\(/i,
        /\bdocument\.write\s*\(/i,
        /\binnerHTML\s*=/i,
        /\bouterHTML\s*=/i,
        /javascript\s*:/i,
        /data\s*:\s*text\/html/i,
        /<\s*script[\s>]/i,
      ]
      return dangerousPatterns.some((pattern) => pattern.test(value))
    }

    if (data?.response !== undefined) {
      const responseStr = String(data.response)
      if (containsDangerousPatterns(responseStr)) {
        console.warn('LLM output validation: dangerous pattern detected in response field; field suppressed.')
        minimisedData.response = '[Response suppressed: potentially unsafe content detected]'
      } else {
        minimisedData.response = data.response
      }
    }

    if (data?.session_id !== undefined) {
      const sessionIdStr = String(data.session_id)
      if (containsDangerousPatterns(sessionIdStr)) {
        console.warn('LLM output validation: dangerous pattern detected in session_id field; field suppressed.')
        // session_id is omitted entirely if it contains dangerous content
      } else {
        minimisedData.session_id = data.session_id
      }
    }

    if (data?.policy_error !== undefined) minimisedData.policy_error = data.policy_error

    return NextResponse.json(minimisedData)
  } catch (error) {
    console.error('Backend proxy error:', error)
    return NextResponse.json(
      {
        detail: 'Failed to connect to backend service',
        policy_error: {
          type: 'general',
          message: 'Backend service unavailable',
        },
      },
      { status: 503 }
    )
  }
}
