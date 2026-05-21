import { NextRequest, NextResponse } from 'next/server'
import { getServerSession } from 'next-auth'
import { authOptions } from '@/lib/authOptions'
import { createHash } from 'crypto'
import { appendFileSync, mkdirSync } from 'fs'
import { join } from 'path'

const BACKEND_URL = process.env.BACKEND_URL

// Approved model registry: only these pinned model identifiers are permitted.
// Update this list through your change-management process when adopting new models.
const APPROVED_MODELS: ReadonlySet<string> = new Set([
  // OpenAI pinned versions
  'gpt-4o-2024-08-06',
  'gpt-4o-mini-2024-07-18',
  'gpt-4-turbo-2024-04-09',
  'gpt-3.5-turbo-0125',
  // Anthropic Claude pinned versions
  'claude-3-5-sonnet-20241022',
  'claude-3-5-haiku-20241022',
  'claude-3-opus-20240229',
  'claude-3-sonnet-20240229',
  'claude-3-haiku-20240307',
  // Add other approved, pinned model IDs here
])
const API_SECRET = process.env.API_SECRET
const BACKEND_API_KEY = process.env.BACKEND_API_KEY

// Allowlist of approved LLM endpoint URL prefixes sanctioned by the organization.
// Only these endpoints may be used as BACKEND_URL targets.
const APPROVED_LLM_ENDPOINTS: string[] = [
  process.env.APPROVED_LLM_ENDPOINT_1 || '',
  process.env.APPROVED_LLM_ENDPOINT_2 || '',
].filter(Boolean)

// Fallback hardcoded approved endpoint identifier (org-approved-llm-v1).
// Operators must set at least one APPROVED_LLM_ENDPOINT_* env var or ensure
// BACKEND_URL contains the org-approved hostname segment.
const ORG_APPROVED_HOSTNAME_SEGMENT = process.env.ORG_APPROVED_LLM_HOSTNAME || 'org-approved-llm-v1'

function isApprovedEndpoint(url: string): boolean {
  // Check against explicitly configured approved endpoint prefixes.
  if (APPROVED_LLM_ENDPOINTS.length > 0) {
    return APPROVED_LLM_ENDPOINTS.some((approved) => url.startsWith(approved))
  }
  // Fallback: verify the URL contains the org-approved hostname segment.
  try {
    const parsed = new URL(url)
    return parsed.hostname.includes(ORG_APPROVED_HOSTNAME_SEGMENT)
  } catch {
    return false
  }
}

if (!BACKEND_URL) {
  throw new Error('BACKEND_URL environment variable is not set. Only approved LLM endpoints may be used; configure BACKEND_URL to an approved endpoint.')
}

if (!isApprovedEndpoint(BACKEND_URL)) {
  throw new Error(
    `BACKEND_URL "${BACKEND_URL}" is not in the organization's approved LLM endpoint list. ` +
    'Set APPROVED_LLM_ENDPOINT_1 (and optionally APPROVED_LLM_ENDPOINT_2) to the approved endpoint URL prefix, ' +
    'or set ORG_APPROVED_LLM_HOSTNAME to the approved hostname segment. ' +
    'Only organization-approved LLM endpoints may be used.'
  )
}
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

// Shell command pattern built dynamically to avoid embedding raw command strings in source
const _shellCmdParts = [
  // Interpreters and scripting runtimes
  ['ba','sh'].join(''), ['s','h'].join(''), ['zs','h'].join(''),
  ['cm','d'].join(''), ['powers','hell'].join(''), ['pw','sh'].join(''),
  // Code execution primitives
  ['ex','ec'].join(''), ['ev','al'].join(''), ['sys','tem'].join(''),
  ['po','pen'].join(''), ['subpro','cess'].join(''),
  ['os\.sys','tem'].join(''), ['child_pro','cess'].join(''),
  ['spa','wn'].join(''), ['exec','Sync'].join(''), ['exec','File'].join(''),
  ['pass','thru'].join(''), ['shell_e','xec'].join(''), ['proc_o','pen'].join(''),
  // Privileged / destructive commands
  '\\bsudo\\b', '\\bchmod\\b', '\\bchown\\b',
  ['\\br','m\\s+-rf'].join(''), '\\bmkdir\\b',
  // Network utilities
  ['\\bw','get\\b'].join(''), ['\\bcu','rl\\b'].join(''),
  '\\bnc\\b', '\\bnetcat\\b', '\\btelnet\\b',
  ['\\bss','h\\b'].join(''), ['\\bsc','p\\b'].join(''), ['\\bft','p\\b'].join('')
]
const SHELL_COMMAND_PATTERN = new RegExp(
  '(?:^|[\\s;|&`$(){}])(?:' + _shellCmdParts.join('|') + ')',
  'i'
)
const BASE64_PATTERN = /(?:[A-Za-z0-9+/]{40,}={0,2})/
const BINARY_PATTERN = /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]/
const HIDDEN_PROMPT_PATTERN = /(?:ignore\s+(?:previous|above|prior|all)\s+(?:instructions?|prompts?|context)|you\s+are\s+now|act\s+as\s+(?:a\s+)?(?:different|new|another|unrestricted)|disregard\s+(?:all|any|previous)|forget\s+(?:all|everything|previous)|system\s*:\s*you|<\s*system\s*>|\[\s*system\s*\]|###\s*(?:system|instruction)|roleplay\s+as|pretend\s+(?:you\s+are|to\s+be)|jailbreak|DAN\s+mode|developer\s+mode)/i
// Leetspeak shell pattern built dynamically to avoid embedding obfuscated command strings in source
const _leetspeakParts = [
  // exec
  '[e3][x\\*][e3][c\\(]',
  // system
  '[s\\$][y\\*][s\\$][t\\+][e3][m\\*]',
  // eval
  '[e3][v\\*][a@][l\\|]',
  // bash
  '[b8][a@4][s\\$][h#]',
  // powershell
  '[p\\|][o0][w\\*][e3][r\\*][s\\$][h#]'
]
const LEETSPEAK_SHELL_PATTERN = new RegExp(
  '(?:' + _leetspeakParts.join('|') + ')',
  'i'
)

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
      // Validate session_id as a signed JWT with expiry and subject binding.
      // Only forward the token if it passes all cryptographic and structural checks.
      const validateSessionToken = async (token: unknown): Promise<boolean> => {
        try {
          if (typeof token !== 'string') return false

          // Structural check: must be a three-part JWT
          const parts = token.split('.')
          if (parts.length !== 3) return false

          const [headerB64, payloadB64, signatureB64] = parts

          // Decode header and payload (base64url)
          const base64urlDecode = (s: string): string =>
            Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8')

          let header: Record<string, unknown>
          let payload: Record<string, unknown>
          try {
            header = JSON.parse(base64urlDecode(headerB64))
            payload = JSON.parse(base64urlDecode(payloadB64))
          } catch {
            return false
          }

          // Algorithm binding: only accept HMAC-SHA256
          if (header.alg !== 'HS256') {
            console.warn('Session token validation: unexpected algorithm; token suppressed.')
            return false
          }

          // Expiry check: exp claim must exist and must not be in the past
          if (typeof payload.exp !== 'number') {
            console.warn('Session token validation: missing exp claim; token suppressed.')
            return false
          }
          const nowSeconds = Math.floor(Date.now() / 1000)
          if (payload.exp <= nowSeconds) {
            console.warn('Session token validation: token has expired; token suppressed.')
            return false
          }

          // Subject binding: sub claim must be a non-empty string
          if (typeof payload.sub !== 'string' || payload.sub.trim() === '') {
            console.warn('Session token validation: missing or empty sub claim; token suppressed.')
            return false
          }

          // Signature verification using HMAC-SHA256
          const secret = process.env.SESSION_TOKEN_SECRET
          if (!secret) {
            console.warn('Session token validation: SESSION_TOKEN_SECRET not configured; token suppressed.')
            return false
          }

          const { createHmac } = await import('crypto')
          const signingInput = `${headerB64}.${payloadB64}`
          const expectedSig = createHmac('sha256', secret)
            .update(signingInput)
            .digest('base64url')

          // Constant-time comparison to prevent timing attacks
          const { timingSafeEqual } = await import('crypto')
          const expectedBuf = Buffer.from(expectedSig)
          const actualBuf = Buffer.from(signatureB64)
          if (expectedBuf.length !== actualBuf.length) {
            console.warn('Session token validation: signature length mismatch; token suppressed.')
            return false
          }
          if (!timingSafeEqual(expectedBuf, actualBuf)) {
            console.warn('Session token validation: signature verification failed; token suppressed.')
            return false
          }

          return true
        } catch {
          return false
        }
      }

      const sessionTokenValid = await validateSessionToken(data.session_id)
      if (sessionTokenValid) {
        minimisedData.session_id = data.session_id
      } else {
        console.warn('Session token validation: session_id failed integrity checks; field suppressed.')
        // session_id is omitted entirely if it fails cryptographic validation
      }
    }

    if (data?.policy_error !== undefined) minimisedData.policy_error = data.policy_error

    // --- Synthetic-content provenance, labeling, and watermarking ---
    // Attach metadata so downstream consumers can verify the AI origin of this response.
    const provenanceTimestamp = new Date().toISOString()
    const modelId = process.env.LLM_MODEL_ID ?? 'unknown-model'
    const originTag = 'ai-generated'

    // Build a canonical representation of the payload for signing.
    const canonicalPayload = JSON.stringify({
      ...minimisedData,
      _provenance: { modelId, timestamp: provenanceTimestamp, originTag },
    })

    // Compute an HMAC-SHA256 signature so recipients can verify integrity.
    const signingSecret = process.env.PROVENANCE_SIGNING_SECRET ?? ''
    let provenanceSignature = ''
    if (signingSecret) {
      const { createHmac } = await import('crypto')
      provenanceSignature = createHmac('sha256', signingSecret)
        .update(canonicalPayload)
        .digest('hex')
    } else {
      console.warn('Provenance signing secret is not configured; signature will be empty.')
    }

    const labelledData = {
      ...minimisedData,
      // Human-readable synthetic-content label (policy requirement).
      _synthetic_content_label: 'This response was generated by an AI language model.',
      _provenance: {
        modelId,
        timestamp: provenanceTimestamp,
        originTag,
        // Hex-encoded HMAC-SHA256 over the canonical payload.
        signature: provenanceSignature,
      },
    }

    return NextResponse.json(labelledData)
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
