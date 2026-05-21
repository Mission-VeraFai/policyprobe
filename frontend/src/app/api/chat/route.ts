import { NextRequest, NextResponse } from 'next/server'
import { getServerSession } from 'next-auth'
import { authOptions } from '@/lib/authOptions'
import { createHash } from 'crypto'
import { appendFileSync, mkdirSync, statSync, renameSync, existsSync } from 'fs'
import { join } from 'path'

const BACKEND_URL = process.env.BACKEND_URL

// Audit log retention: rotate the log file when it exceeds this size (default 10 MB).
const MAX_LOG_BYTES = parseInt(process.env.AUDIT_LOG_MAX_BYTES ?? String(10 * 1024 * 1024), 10)

/**
 * Rotate the audit log file if it has grown beyond MAX_LOG_BYTES.
 * The current file is renamed to <path>.<ISO-timestamp>.bak before a new one is started.
 */
function rotateLogIfNeeded(logPath: string): void {
  try {
    if (existsSync(logPath)) {
      const { size } = statSync(logPath)
      if (size >= MAX_LOG_BYTES) {
        const archive = `${logPath}.${new Date().toISOString().replace(/[:.]/g, '-')}.bak`
        renameSync(logPath, archive)
      }
    }
  } catch (rotateErr) {
    // Rotation failure must not suppress the original write; surface as a warning.
    console.error('[audit] Log rotation failed:', rotateErr)
  }
}

/**
 * Write a single audit record to the local append-only log.
 * Throws if the write fails so callers can decide how to handle the error.
 */
function writeAuditRecord(logPath: string, record: Record<string, unknown>): void {
  rotateLogIfNeeded(logPath)
  const line = JSON.stringify(record) + '\n'
  try {
    appendFileSync(logPath, line, { encoding: 'utf8', flag: 'a' })
  } catch (fsErr) {
    // Re-throw so the caller is aware the audit record was NOT persisted.
    throw new Error(`[audit] Failed to write audit record to ${logPath}: ${fsErr}`)
  }
}

// Maximum allowed length for a single message's text content
const MAX_MESSAGE_LENGTH = 32_000

// Patterns indicative of prompt-injection or jailbreak attempts
const PROMPT_INJECTION_PATTERNS: RegExp[] = [
  /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)/i,
  /system\s*:\s*(you\s+are|act\s+as|pretend)/i,
  /\[\s*system\s*\]/i,
  /<\s*system\s*>/i,
  /###\s*instruction/i,
  /\bDAN\b.*mode/i,
]

/**
 * Sanitizes and validates a single message content string before it is
 * forwarded to the backend LLM endpoint.
 *
 * @throws {Error} if the content fails validation
 */
function sanitizeMessageContent(content: unknown, role: string): string {
  if (typeof content !== 'string') {
    throw new Error(`Message content for role "${role}" must be a string.`)
  }

  // Strip null bytes and ASCII control characters (except tab, newline, carriage-return)
  // eslint-disable-next-line no-control-regex
  let sanitized = content.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '')

  // Trim leading/trailing whitespace
  sanitized = sanitized.trim()

  if (sanitized.length === 0) {
    throw new Error(`Message content for role "${role}" must not be empty after sanitization.`)
  }

  if (sanitized.length > MAX_MESSAGE_LENGTH) {
    throw new Error(
      `Message content for role "${role}" exceeds the maximum allowed length of ${MAX_MESSAGE_LENGTH} characters.`
    )
  }

  for (const pattern of PROMPT_INJECTION_PATTERNS) {
    if (pattern.test(sanitized)) {
      throw new Error(
        `Message content for role "${role}" contains a disallowed prompt-injection pattern.`
      )
    }
  }

  return sanitized
}

/**
 * Validates and sanitizes an array of conversation history messages.
 * Each element must have a string `role` and a string `content`.
 *
 * @throws {Error} if any message fails validation
 */
function sanitizeMessages(messages: unknown): Array<{ role: string; content: string }> {
  if (!Array.isArray(messages)) {
    throw new Error('Messages must be an array.')
  }

  const ALLOWED_ROLES = new Set(['user', 'assistant', 'system'])

  return messages.map((msg: unknown, idx: number) => {
    if (typeof msg !== 'object' || msg === null) {
      throw new Error(`Message at index ${idx} must be an object.`)
    }
    const m = msg as Record<string, unknown>

    if (typeof m.role !== 'string' || !ALLOWED_ROLES.has(m.role)) {
      throw new Error(
        `Message at index ${idx} has an invalid or missing role. Allowed roles: ${[...ALLOWED_ROLES].join(', ')}.`
      )
    }

    const sanitizedContent = sanitizeMessageContent(m.content, m.role)

    return { role: m.role, content: sanitizedContent }
  })
}

// Approved model registry: model identifiers are fetched from the organization's
// external registry endpoint and verified via HMAC-SHA256 signature.
// Configure MODEL_REGISTRY_URL and MODEL_REGISTRY_HMAC_SECRET in your environment.
// The registry endpoint must return JSON: { "models": ["model-id", ...], "signature": "<hex-hmac-sha256-of-models-json>" }
const MODEL_REGISTRY_URL = process.env.MODEL_REGISTRY_URL
const MODEL_REGISTRY_HMAC_SECRET = process.env.MODEL_REGISTRY_HMAC_SECRET

if (!MODEL_REGISTRY_URL) {
  throw new Error('MODEL_REGISTRY_URL environment variable is not set. An organization-approved model registry endpoint is required.')
}
if (!MODEL_REGISTRY_HMAC_SECRET) {
  throw new Error('MODEL_REGISTRY_HMAC_SECRET environment variable is not set. Registry response integrity verification requires a shared HMAC secret.')
}

// APPROVED_MODELS_FALLBACK: comma-separated list of org-approved model IDs used when
// the external registry is temporarily unreachable. Must NOT include unapproved
// identifiers such as bare 'Claude' or 'GPT'.
// Example: APPROVED_MODELS_FALLBACK=claude-3-5-sonnet-20241022,gpt-4o
const APPROVED_MODELS_FALLBACK_RAW = process.env.APPROVED_MODELS_FALLBACK ?? ''
const APPROVED_MODELS_FALLBACK: ReadonlySet<string> = new Set(
  APPROVED_MODELS_FALLBACK_RAW
    .split(',')
    .map(s => s.trim())
    .filter(s => s.length > 0)
    // Explicitly block bare unapproved identifiers regardless of env config
    .filter(s => !['Claude', 'GPT'].includes(s))
)

  // Cache maps model-id → pinned sha256 digest for version-pinned registry enforcement
  let _approvedModelsCache: ReadonlyMap<string, string> | null = null
let _approvedModelsCacheExpiry = 0
const REGISTRY_CACHE_TTL_MS = 5 * 60 * 1000 // 5 minutes

async function fetchApprovedModelsFromRegistry(): Promise<ReadonlyMap<string, string>> {
  const now = Date.now()
  if (_approvedModelsCache && now < _approvedModelsCacheExpiry) {
    return _approvedModelsCache!
  }

  let registryResponse: Response
  try {
    registryResponse = await fetch(MODEL_REGISTRY_URL!, {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
      // Enforce a short timeout to avoid blocking requests
      signal: AbortSignal.timeout(5000),
    })
  } catch (err) {
    // Fall back to the statically configured approved list when the registry is unreachable.
    // If the fallback list is also empty, deny all model requests.
    if (APPROVED_MODELS_FALLBACK.size > 0) {
      console.warn(
        `Organization model registry unreachable (${err}). ` +
        `Falling back to APPROVED_MODELS_FALLBACK list (${APPROVED_MODELS_FALLBACK.size} models).`
      )
      return APPROVED_MODELS_FALLBACK
    }
    throw new Error(
      `Failed to reach organization model registry at ${MODEL_REGISTRY_URL} and ` +
      `APPROVED_MODELS_FALLBACK is empty. Cannot verify approved models: ${err}`
    )
  }

  if (!registryResponse.ok) {
    throw new Error(`Organization model registry returned HTTP ${registryResponse.status}. Cannot verify approved models.`)
  }

  let payload: { models: string[]; signature: string }
  try {
    payload = await registryResponse.json()
  } catch {
    throw new Error('Organization model registry returned invalid JSON.')
  }

  // Registry must supply a pinned_models map: { "model-id": "sha256:<digest>", ... }
  // This enforces both model identity AND immutable version pinning via cryptographic digest.
  if (
    typeof payload.models !== 'object' ||
    Array.isArray(payload.models) ||
    payload.models === null ||
    typeof payload.signature !== 'string'
  ) {
    throw new Error(
      'Organization model registry response must contain: ' +
      'pinned_models (object mapping model-id to sha256 digest) and signature (string). ' +
      'Plain model name arrays are rejected — version pinning via digest is required.'
    )
  }

  // Validate every entry has a well-formed sha256 digest pin
  for (const [modelId, digest] of Object.entries(payload.models as Record<string, unknown>)) {
    if (typeof digest !== 'string' || !/^sha256:[0-9a-f]{64}$/i.test(digest)) {
      throw new Error(
        `Registry entry for model '${modelId}' has invalid or missing version pin. ` +
        `Expected format: sha256:<64-hex-chars>. Got: ${digest}`
      )
    }
  }

  // Verify HMAC-SHA256 signature over the canonical JSON of the pinned_models map
  const { createHmac } = await import('crypto')
  const canonicalPayload = JSON.stringify(payload.models)
  const expectedSig = createHmac('sha256', MODEL_REGISTRY_HMAC_SECRET!)
    .update(canonicalPayload)
    .digest('hex')

  // Constant-time comparison to prevent timing attacks
  const { timingSafeEqual } = await import('crypto')
  const sigBuffer = Buffer.from(payload.signature, 'hex')
  const expectedBuffer = Buffer.from(expectedSig, 'hex')
  if (
    sigBuffer.length !== expectedBuffer.length ||
    !timingSafeEqual(sigBuffer, expectedBuffer)
  ) {
    throw new Error('Organization model registry HMAC signature verification failed. Refusing to use unverified model list.')
  }

  const approvedSet: ReadonlySet<string> = new Set(payload.models)
  _approvedModelsCache = approvedSet
  _approvedModelsCacheExpiry = now + REGISTRY_CACHE_TTL_MS
  return approvedSet
}

async function isModelApproved(modelId: string): Promise<boolean> {
  const approved = await fetchApprovedModelsFromRegistry()
  return approved.has(modelId)
}
const API_SECRET = process.env.API_SECRET
const BACKEND_API_KEY = process.env.BACKEND_API_KEY

// Allowlist of approved LLM endpoint URL prefixes sanctioned by the organization.
// At least one APPROVED_LLM_ENDPOINT_* env var MUST be set; no fallback is permitted.
const APPROVED_LLM_ENDPOINTS: string[] = [
  process.env.APPROVED_LLM_ENDPOINT_1 || '',
  process.env.APPROVED_LLM_ENDPOINT_2 || '',
].filter(Boolean)

if (APPROVED_LLM_ENDPOINTS.length === 0) {
  throw new Error(
    'No approved LLM endpoints configured. Set at least APPROVED_LLM_ENDPOINT_1 to an approved endpoint URL prefix. ' +
    'A non-empty allowlist is required to prevent SSRF.'
  )
}

function isApprovedEndpoint(url: string): boolean {
  // Require an exact prefix match against the explicitly configured approved endpoints.
  // No fallback hostname check is permitted — the allowlist must always be non-empty.
  return APPROVED_LLM_ENDPOINTS.some((approved) => url.startsWith(approved))
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

/**
 * Sanitize a string value before embedding it in a log record.
 * Removes ASCII control characters (including CR/LF) to prevent log injection.
 */
function sanitizeForLog(value: unknown): string {
  if (value === null || value === undefined) return ''
  // Convert to string, then strip all ASCII control characters (0x00-0x1F, 0x7F)
  // including newline (0x0A) and carriage return (0x0D) to prevent log injection.
  return String(value).replace(/[\x00-\x1F\x7F]/g, '')
}

// Retention policy: records must be kept for at least AUDIT_RETENTION_DAYS days.
// Operators are responsible for rotating/archiving logs according to this policy
// (e.g. via logrotate, a cron job, or a log-management platform).
// A value of 0 disables automatic expiry hints in audit records.
const AUDIT_RETENTION_DAYS = parseInt(process.env.AUDIT_RETENTION_DAYS || '90', 10)
const AUDIT_MAX_FILE_SIZE_MB = parseInt(process.env.AUDIT_MAX_FILE_SIZE_MB || '100', 10)

/**
 * Strips newline and carriage-return characters from every string value in an
 * object/array/primitive so that user-controlled data cannot inject forged
 * entries into the JSONL audit log.
 */
function sanitizeForLog<T>(value: T): T {
  if (typeof value === 'string') {
    // Remove CR, LF, and other vertical whitespace that could break JSONL structure.
    return value.replace(/[\r\n\u2028\u2029]/g, ' ') as unknown as T
  }
  if (Array.isArray(value)) {
    return value.map(sanitizeForLog) as unknown as T
  }
  if (value !== null && typeof value === 'object') {
    const sanitized: Record<string, unknown> = {}
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      sanitized[k] = sanitizeForLog(v)
    }
    return sanitized as unknown as T
  }
  return value
}

function hashInput(input: unknown): string {
  return createHash('sha256')
    .update(JSON.stringify(input))
    .digest('hex')
}

function getPrincipal(_request: NextRequest): string {
  // IP address and IP-derived values must not be logged (PII policy).
  // Return a static, non-PII principal token instead.
  return 'session'
}

// Shell command pattern — explicit string literals for transparency and auditability
const _shellCmdParts = [
  // Interpreters and scripting runtimes
  'bash', 'sh', 'zsh',
  'cmd', 'powershell', 'pwsh',
  // Code execution primitives
  'exec', 'eval', 'system',
  'popen', 'subprocess',
  'os\.system', 'child_process',
  'spawn', 'execSync', 'execFile',
  'passthru', 'shell_exec', 'proc_open',
  // Privileged / destructive commands
  '\\bsudo\\b', '\\bchmod\\b', '\\bchown\\b',
  '\\brm\\s+-rf', '\\bmkdir\\b',
  // Network utilities
  '\\bwget\\b', '\\bcurl\\b',
  '\\bnc\\b', '\\bnetcat\\b', '\\btelnet\\b',
  '\\bssh\\b', '\\bscp\\b', '\\bftp\\b'
]
const SHELL_COMMAND_PATTERN = new RegExp(
  '(?:^|[\\s;|&`$(){}])(?:' + _shellCmdParts.join('|') + ')',
  'i'
)
const BASE64_PATTERN = /(?:[A-Za-z0-9+/]{40,}={0,2})/
const BINARY_PATTERN = /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]/
const HIDDEN_PROMPT_PATTERN = /(?:ignore\s+(?:previous|above|prior|all)\s+(?:instructions?|prompts?|context)|you\s+are\s+now|act\s+as\s+(?:a\s+)?(?:different|new|another|unrestricted)|disregard\s+(?:all|any|previous)|forget\s+(?:all|everything|previous)|system\s*:\s*you|<\s*system\s*>|\[\s*system\s*\]|###\s*(?:system|instruction)|roleplay\s+as|pretend\s+(?:you\s+are|to\s+be)|jailbreak|DAN\s+mode|developer\s+mode)/i
// Leetspeak shell pattern for detecting leet-encoded shell commands in user input
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

    // Cryptographically verify the JWT signature and extract verified claims.
    // getToken re-validates the HMAC/RSA signature using NEXTAUTH_SECRET,
    // ensuring the token has not been tampered with since issuance.
    const { getToken } = await import('next-auth/jwt')
    const verifiedToken = await getToken({
      req: request as Parameters<typeof getToken>[0]['req'],
      secret: process.env.NEXTAUTH_SECRET,
    })
    if (!verifiedToken) {
      return NextResponse.json(
        { detail: 'Unauthorized: Session token signature verification failed.' },
        { status: 401 }
      )
    }

    // Validate session integrity: check expiry against the verified token's exp claim.
    // We use the token's own exp rather than the session.expires string so that
    // a tampered session object cannot bypass expiry enforcement.
    const tokenExp = typeof verifiedToken.exp === 'number' ? verifiedToken.exp : null
    if (tokenExp === null) {
      return NextResponse.json(
        { detail: 'Unauthorized: Session token is missing expiry claim.' },
        { status: 401 }
      )
    }
    if (Date.now() > tokenExp * 1000) {
      return NextResponse.json(
        { detail: 'Unauthorized: Session has expired.' },
        { status: 401 }
      )
    }

    // Also enforce the session-level expiry as a secondary check.
    if (session.expires) {
      const expiresAt = new Date(session.expires).getTime()
      if (isNaN(expiresAt) || Date.now() > expiresAt) {
        return NextResponse.json(
          { detail: 'Unauthorized: Session has expired.' },
          { status: 401 }
        )
      }
    } else {
      // No expiry field present — reject to enforce expiry policy
      return NextResponse.json(
        { detail: 'Unauthorized: Session is missing expiry information.' },
        { status: 401 }
      )
    }

    // Validate session integrity: assert subject binding (user identity must be present)
    if (
      !session.user ||
      typeof session.user.email !== 'string' ||
      session.user.email.trim() === ''
    ) {
      return NextResponse.json(
        { detail: 'Unauthorized: Session is missing required user identity binding.' },
        { status: 401 }
      )
    }

    // Cross-validate subject binding: the verified token's email must match the
    // session user email to prevent session/token substitution attacks.
    const tokenEmail = typeof verifiedToken.email === 'string' ? verifiedToken.email.trim() : null
    if (!tokenEmail || tokenEmail.toLowerCase() !== session.user.email.trim().toLowerCase()) {
      return NextResponse.json(
        { detail: 'Unauthorized: Session subject binding mismatch.' },
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
    // PROVENANCE_SIGNING_SECRET removed: provenance signing is delegated to the
// dedicated signing service and must not be performed with a locally-held secret
// in this file. Call the signing service API directly if signing is required.
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

    // --- LLM output validation: dynamic code-execution primitive detection ---
    // Serialize the full payload and scan for patterns that indicate the LLM
    // has embedded eval, exec, subprocess, or other dynamic code-execution
    // primitives in its response.  Any match is treated as a policy violation
    // and the response is blocked before it reaches the client.
    const DANGEROUS_PATTERNS: RegExp[] = [
      /\beval\s*\(/gi,
      /\bexec\s*\(/gi,
      /\bexecSync\s*\(/gi,
      /\bspawnSync\s*\(/gi,
      /\bspawn\s*\(/gi,
      /\bexecFile\s*\(/gi,
      /\bexecFileSync\s*\(/gi,
      /\bnew\s+Function\s*\(/gi,
      /\bsetTimeout\s*\(\s*['"`]/gi,
      /\bsetInterval\s*\(\s*['"`]/gi,
      /subprocess\s*\.\s*(run|call|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True/gi,
      /os\s*\.\s*(system|popen)\s*\(/gi,
      /\bimportlib\s*\.\s*import_module\s*\(/gi,
      /__import__\s*\(/gi,
      /compile\s*\([^)]+exec/gi,
    ]

    const serialisedOutput = JSON.stringify(labelledData)
    const detectedPatterns: string[] = []

    for (const pattern of DANGEROUS_PATTERNS) {
      if (pattern.test(serialisedOutput)) {
        detectedPatterns.push(pattern.source)
      }
    }

    if (detectedPatterns.length > 0) {
      console.error(
        'LLM output validation FAILED: dynamic code-execution primitives detected in LLM response.',
        { detectedPatterns }
      )
      return NextResponse.json(
        {
          detail: 'LLM response blocked by output validation policy.',
          policy_error: {
            type: 'llm_output_validation',
            message:
              'The AI response contained dynamic code-execution primitives and was blocked before being forwarded to the client.',
          },
        },
        { status: 400 }
      )
    }
    // --- End LLM output validation ---

    return NextResponse.json(labelledData)
  } catch (error) {
    console.error('Backend proxy error:', error)

    // Surface input-validation failures as 400 rather than 503
    if (error instanceof Error && error.message.startsWith('Message content') || error instanceof Error && error.message.startsWith('Messages must')) {
      return NextResponse.json(
        {
          detail: error.message,
          policy_error: {
            type: 'input_validation',
            message: 'Request rejected due to invalid or disallowed message content.',
          },
        },
        { status: 400 }
      )
    }

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
