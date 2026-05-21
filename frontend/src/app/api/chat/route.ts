import { NextRequest, NextResponse } from 'next/server'
import { getServerSession } from 'next-auth'
import { authOptions } from '@/lib/authOptions'
import { createHash } from 'crypto'
import { appendFileSync, mkdirSync } from 'fs'
import { join } from 'path'

const BACKEND_URL = process.env.BACKEND_URL || 'http://127.0.0.1:5500'
const API_SECRET = process.env.API_SECRET
const BACKEND_API_KEY = process.env.BACKEND_API_KEY

if (!BACKEND_API_KEY) {
  throw new Error('BACKEND_API_KEY environment variable is not set. Inter-agent communication requires authentication.')
}
const AUDIT_LOG_DIR = process.env.AUDIT_LOG_DIR || join(process.cwd(), 'audit-logs')
const AUDIT_LOG_FILE = join(AUDIT_LOG_DIR, 'ai-chat-audit.jsonl')

function hashInput(input: unknown): string {
  return createHash('sha256')
    .update(JSON.stringify(input))
    .digest('hex')
}

function getPrincipal(request: NextRequest): string {
  const forwarded = request.headers.get('x-forwarded-for')
  const realIp = request.headers.get('x-real-ip')
  if (forwarded) return forwarded.split(',')[0].trim()
  if (realIp) return realIp
  return 'unknown'
}

function writeAuditRecord(record: Record<string, unknown>): void {
  try {
    mkdirSync(AUDIT_LOG_DIR, { recursive: true })
    appendFileSync(AUDIT_LOG_FILE, JSON.stringify(record) + '\n', { encoding: 'utf8', flag: 'a' })
  } catch (auditErr) {
    console.error('[AUDIT] Failed to write audit record:', auditErr)
  }
}

export async function POST(request: NextRequest) {
  try {
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

    const response = await fetch(`${BACKEND_URL}/chat`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(allowedBody),
    })

    const data = await response.json()

    // Derive model identifier from response payload or request body (best-effort)
    const modelId: string =
      (data as Record<string, unknown>)?.model as string ||
      (body as Record<string, unknown>)?.model as string ||
      'unknown'

    if (!response.ok) {
      writeAuditRecord({
        timestamp,
        principal,
        model: modelId,
        inputHash,
        httpStatus: response.status,
        outcome: 'backend_error',
        output: data,
      })
      return NextResponse.json(data, { status: response.status })
    }

    writeAuditRecord({
      timestamp,
      principal,
      model: modelId,
      inputHash,
      httpStatus: 200,
      outcome: 'success',
      output: data,
    })

    return NextResponse.json(data)
  } catch (error) {
    writeAuditRecord({
      timestamp,
      principal,
      model: (body as Record<string, unknown>)?.model as string || 'unknown',
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

    if (!response.ok) {
      // Minimise error responses — only expose safe, known fields
      const errorPayload: Record<string, unknown> = {}
      if (data?.detail !== undefined) errorPayload.detail = data.detail
      if (data?.policy_error !== undefined) errorPayload.policy_error = data.policy_error
      return NextResponse.json(errorPayload, { status: response.status })
    }

    // Minimise success responses — only expose safe, known fields
    const minimisedData: Record<string, unknown> = {}
    if (data?.response !== undefined) minimisedData.response = data.response
    if (data?.session_id !== undefined) minimisedData.session_id = data.session_id
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
