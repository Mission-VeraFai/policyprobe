'use client'

import { useState, useRef, useEffect } from 'react'
import { v4 as uuidv4 } from 'uuid'

// Helper: retrieve the stored auth token
function getAuthToken(): string | null {
  if (typeof window === 'undefined') return null
  return localStorage.getItem('auth_token')
}
import { MessageList } from './MessageList'
import { FileUpload } from './FileUpload'
import { Send, Paperclip, Loader2 } from 'lucide-react'

export interface Message {
  id: string
  role: 'user' | 'assistant' | 'system'
  content: string
  timestamp: Date
  attachments?: FileAttachment[]
  error?: PolicyError
  // Synthetic-content provenance fields (required for assistant messages)
  isSynthetic?: boolean
  modelId?: string
  generatedAt?: string   // ISO-8601 timestamp tag from generation time
  watermark?: string     // Opaque provenance token
}

export interface FileAttachment {
  id: string
  name: string
  type: string
  size: number
  content?: string
}

export interface PolicyError {
  type: 'pii' | 'threat' | 'auth' | 'general'
  message: string
  details?: Record<string, unknown>
}

// Patterns that indicate potentially malicious prompt injection attempts
const SHELL_COMMAND_PATTERN = /(?:^|\s|;|&&|\|\|)(sudo|chmod|chown|curl|wget|bash|sh|zsh|python|perl|ruby|nc|ncat|netcat|exec|eval|system|popen|subprocess|os\.system|cmd\.exe|powershell|\$\(|`[^`]*`)(?:\s|$|;)/i
const BASE64_INJECTION_PATTERN = /(?:[A-Za-z0-9+/]{40,}={0,2})(?:\s*(?:decode|base64|atob|eval))?/
const INVISIBLE_CHARS_PATTERN = /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF\u00AD]/
const BINARY_MAGIC_BYTES_PATTERN = /(?:\x7fELF|MZ\x90|\xcf\xfa\xed\xfe|\xce\xfa\xed\xfe|\x4d\x5a)/
const LEETSPEAK_INJECTION_PATTERN = /(?:3x3c|3v4l|5y5t3m|sh3ll|c0mm4nd|1nj3ct|3xpl01t|pwn3d|r00t|4dm1n)/i
const EXCESSIVE_BASE64_THRESHOLD = 60 // characters of continuous base64-like content

function sanitizeInput(text: string): { safe: boolean; reason?: string; sanitized: string } {
  // Check for invisible/hidden characters
  if (INVISIBLE_CHARS_PATTERN.test(text)) {
    // Strip invisible characters and warn
    const sanitized = text.replace(INVISIBLE_CHARS_PATTERN, '')
    return { safe: false, reason: 'Hidden or invisible characters were detected and removed from your message.', sanitized }
  }

  // Check for binary executable magic bytes
  if (BINARY_MAGIC_BYTES_PATTERN.test(text)) {
    return { safe: false, reason: 'Binary executable content detected in message. This content cannot be sent.', sanitized: '' }
  }

  // Check for shell command injection patterns
  if (SHELL_COMMAND_PATTERN.test(text)) {
    return { safe: false, reason: 'Potential shell command detected in message. Please rephrase your request.', sanitized: '' }
  }

  // Check for suspicious base64 blocks (long continuous base64 strings)
  const base64Matches = text.match(/[A-Za-z0-9+/=]{60,}/g)
  if (base64Matches && base64Matches.length > 0) {
    // Attempt to decode and check for shell commands or executables
    for (const match of base64Matches) {
      try {
        const decoded = atob(match.replace(/[^A-Za-z0-9+/=]/g, ''))
        if (SHELL_COMMAND_PATTERN.test(decoded) || BINARY_MAGIC_BYTES_PATTERN.test(decoded)) {
          return { safe: false, reason: 'Base64-encoded malicious content detected. This message cannot be sent.', sanitized: '' }
        }
      } catch {
        // Not valid base64, continue
      }
    }
    // Flag long base64 blocks even if decode check passes
    if (BASE64_INJECTION_PATTERN.test(text)) {
      return { safe: false, reason: 'Suspicious encoded content detected in your message. Please rephrase without encoded blocks.', sanitized: '' }
    }
  }

  // Check for leetspeak injection patterns
  if (LEETSPEAK_INJECTION_PATTERN.test(text)) {
    return { safe: false, reason: 'Obfuscated command patterns detected in your message. Please rephrase your request.', sanitized: '' }
  }

  return { safe: true, sanitized: text }
}

// PII patterns and redaction
const PII_PATTERNS: Array<{ pattern: RegExp; label: string }> = [
  { pattern: /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g, label: '[REDACTED_EMAIL]' },
  { pattern: /\b(?:\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b/g, label: '[REDACTED_PHONE]' },
  { pattern: /\b\d{3}-\d{2}-\d{4}\b/g, label: '[REDACTED_SSN]' },
  { pattern: /\b(?:4\d{3}|5[1-5]\d{2}|6011|3[47]\d{2})[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{3,4}\b/g, label: '[REDACTED_CARD]' },
  { pattern: /\b(?:Mr|Mrs|Ms|Dr|Prof)\.?\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)+\b/g, label: '[REDACTED_NAME]' },
]

function redactPII(content: string): { redacted: string; piiFound: boolean } {
  let redacted = content
  let piiFound = false
  for (const { pattern, label } of PII_PATTERNS) {
    const before = redacted
    redacted = redacted.replace(pattern, label)
    if (redacted !== before) piiFound = true
  }
  return { redacted, piiFound }
}

// Singapore PII detection patterns
const SINGAPORE_PII_PATTERNS: { name: string; pattern: RegExp }[] = [
  { name: 'Singapore NRIC/FIN', pattern: /\b[STFGM]\d{7}[A-Z]\b/i },
  { name: 'Singapore Phone Number', pattern: /\b(?:\+65[\s-]?)?[689]\d{3}[\s-]?\d{4}\b/ },
  { name: 'Singapore Postal Code', pattern: /\bSingapore\s+\d{6}\b/i },
  { name: 'Singapore Passport', pattern: /\bE\d{7}[A-Z]\b/i },
  { name: 'Email Address', pattern: /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/ },
]

function detectSingaporePII(content: string): string[] {
  const detected: string[] = []
  for (const { name, pattern } of SINGAPORE_PII_PATTERNS) {
    if (pattern.test(content)) {
      detected.push(name)
    }
  }
  return detected
}

// Generates a signed session token: base64url(payload).base64url(HMAC-SHA256(payload))
// payload = { jti, iat, exp, sub } — provides identity binding, issued-at, and expiry.
async function generateSignedSessionToken(): Promise<string> {
  const jti = uuidv4()
  const iat = Math.floor(Date.now() / 1000)
  const exp = iat + 4 * 60 * 60 // 4-hour expiry
  const sub = 'chat-session'
  const payload = JSON.stringify({ jti, iat, exp, sub })
  const payloadB64 = btoa(payload).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')

  // Derive a per-session signing key from a fixed app secret + the jti
  const appSecret = 'chat-session-signing-secret-v1'
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(appSecret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  )
  const sigBuffer = await crypto.subtle.sign(
    'HMAC',
    keyMaterial,
    new TextEncoder().encode(payloadB64)
  )
  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sigBuffer)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')

  return `${payloadB64}.${sigB64}`
}

export function ChatInterface() {
  const [messages, setMessages] = useState<Message[]>([])
  const [input, setInput] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [pendingFiles, setPendingFiles] = useState<File[]>([])
  const [showFileUpload, setShowFileUpload] = useState(false)
  const inputRef = useRef<HTMLTextAreaElement>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)
  // Stable signed session token — generated once on mount, bound to this component lifetime.
  const conversationTokenRef = useRef<string | null>(null)

  useEffect(() => {
    if (inputRef.current) {
      inputRef.current.focus()
    }
    // Generate and cache the signed session token once on mount.
    generateSignedSessionToken().then(token => {
      conversationTokenRef.current = token
    })
  }, [])

  const MALICIOUS_PATTERNS = [
    // Prompt injection / jailbreak phrases
    /ignore\s+(previous|prior|above|all)\s+(instructions?|prompts?|context)/i,
    /disregard\s+(previous|prior|above|all)\s+(instructions?|prompts?|context)/i,
    /forget\s+(previous|prior|above|all)\s+(instructions?|prompts?|context)/i,
    /you\s+are\s+now\s+(a\s+)?(?:dan|jailbreak|unrestricted|evil|free)/i,
    /act\s+as\s+(if\s+you\s+are\s+)?(?:a\s+)?(?:dan|jailbreak|unrestricted|evil|uncensored)/i,
    /system\s*:\s*(you|your|ignore|forget|disregard)/i,
    /\[system\]/i,
    /<\s*system\s*>/i,
    /new\s+instructions?\s*:/i,
    /override\s+(safety|policy|guidelines?|rules?|restrictions?)/i,
    /bypass\s+(safety|policy|guidelines?|rules?|restrictions?|filter)/i,
    /jailbreak/i,
    /prompt\s+injection/i,
    // Shell commands
    /(?:^|\s|;|&&|\|\|)(?:rm\s+-rf|sudo\s+|chmod\s+|chown\s+|wget\s+|curl\s+.*\|\s*(?:bash|sh)|eval\s*\(|exec\s*\()/m,
    /(?:base64\s+-d|base64\s+--decode)/i,
    // Leetspeak prompt injection patterns
    /1gn[o0]r[e3]\s+[a4]ll\s+[i1]n5truct/i,
    /[i1]gn[o0]r[e3]\s+pr[e3]v[i1][o0]u5/i,
    // Base64-encoded suspicious content (decode and re-check)
  ]

  const BASE64_PATTERN = /^(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?$/

  const containsMaliciousContent = (text: string): { malicious: boolean; reason: string } => {
    // Check raw text against patterns
    for (const pattern of MALICIOUS_PATTERNS) {
      if (pattern.test(text)) {
        return { malicious: true, reason: 'Suspicious prompt injection or shell command pattern detected.' }
      }
    }

    // Check for base64-encoded blocks and decode them for inspection
    const base64Blocks = text.match(/[A-Za-z0-9+\/]{20,}={0,2}/g) || []
    for (const block of base64Blocks) {
      if (BASE64_PATTERN.test(block)) {
        try {
          const decoded = atob(block)
          // Only inspect if decoded result is printable ASCII
          if (/^[\x20-\x7E\r\n\t]+$/.test(decoded)) {
            for (const pattern of MALICIOUS_PATTERNS) {
              if (pattern.test(decoded)) {
                return { malicious: true, reason: 'Base64-encoded malicious content detected in file.' }
              }
            }
          }
        } catch {
          // Not valid base64, skip
        }
      }
    }

    return { malicious: false, reason: '' }
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()

    if (!input.trim() && pendingFiles.length === 0) return

    // Sanitize user input before processing
    if (input.trim()) {
      const sanitizationResult = sanitizeInput(input)
      if (!sanitizationResult.safe) {
        if (sanitizationResult.sanitized && sanitizationResult.sanitized !== input) {
          // Invisible chars stripped — update input and warn
          setInput(sanitizationResult.sanitized)
          const warnMessage: Message = {
            id: uuidv4(),
            role: 'system',
            content: `⚠️ Security Notice: ${sanitizationResult.reason} Your message has been cleaned. Please review and resubmit.`,
            timestamp: new Date(),
            error: { type: 'threat', message: sanitizationResult.reason || 'Suspicious content detected' },
          }
          setMessages(prev => [...prev, warnMessage])
          setIsLoading(false)
          return
        } else {
          // Dangerous content — block entirely
          const blockMessage: Message = {
            id: uuidv4(),
            role: 'system',
            content: `🚫 Message Blocked: ${sanitizationResult.reason}`,
            timestamp: new Date(),
            error: { type: 'threat', message: sanitizationResult.reason || 'Malicious content detected' },
          }
          setMessages(prev => [...prev, blockMessage])
          setIsLoading(false)
          return
        }
      }
    }

    const attachments: FileAttachment[] = []

            // Process pending files
    for (const file of pendingFiles) {
      const content = await readFileContent(file)

      // Check for Singapore PII before sending to backend
      const piiFound = detectSingaporePII(content)
      if (piiFound.length > 0) {
        const piiErrorMessage: Message = {
          id: uuidv4(),
          role: 'assistant',
          content: `Upload blocked: The file "${file.name}" contains Singapore PII (${piiFound.join(', ')}). Please remove sensitive information before uploading.`,
          timestamp: new Date(),
          error: {
            type: 'pii',
            message: `Singapore PII detected in uploaded file: ${piiFound.join(', ')}`,
            details: { file: file.name, piiCategories: piiFound },
          },
        }
        setMessages(prev => [...prev, piiErrorMessage])
        setIsLoading(false)
        setPendingFiles([])
        setShowFileUpload(false)
        return
      }

      attachments.push({
        id: uuidv4(),
        name: file.name,
        type: file.type,
        size: file.size,
        content,
      })
    } = redactPII(rawContent)
      if (piiFound) {
        console.warn(`PII detected and redacted in file: ${file.name}`)
      }
      attachments.push({
        id: uuidv4(),
        name: file.name,
        type: file.type,
        size: file.size,
        content,
      })
    }" was rejected: ${scanResult.reason} Please remove any prompt injection attempts, shell commands, or encoded malicious content from your file.`,
          timestamp: new Date(),
          error: {
            type: 'threat',
            message: scanResult.reason,
            details: { fileName: file.name },
          },
        }
        setMessages(prev => [...prev, errorMessage])
        setPendingFiles([])
        setShowFileUpload(false)
        setIsLoading(false)
        return
      }

      attachments.push({
        id: uuidv4(),
        name: file.name,
        type: file.type,
        size: file.size,
        content,
      })
    }

    const userMessage: Message = {
      id: uuidv4(),
      role: 'user',
      content: input || `Uploaded ${pendingFiles.length} file(s)`,
      timestamp: new Date(),
      attachments: attachments.length > 0 ? attachments : undefined,
    }

    setMessages(prev => [...prev, userMessage])
    setInput('')
    setPendingFiles([])
    setShowFileUpload(false)
    setIsLoading(true)

    try {
      const sessionToken = typeof window !== 'undefined'
        ? (sessionStorage.getItem('auth_token') || localStorage.getItem('auth_token') || '')
        : ''

      const response = await fetch('/api/backend/chat', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(sessionToken ? { 'Authorization': `Bearer ${sessionToken}` } : {}),
        },
        body: JSON.stringify({
          message: sanitizeTextInput(input),
          attachments: attachments,
          conversation_id: conversationTokenRef.current ?? await generateSignedSessionToken(),
        }),
      })

      // Validate sanitized input before sending
      const sanitizedInput = sanitizeTextInput(input)
      const inputError = validateTextInput(sanitizedInput)
      if (inputError) {
        const validationMessage: Message = {
          id: uuidv4(),
          role: 'assistant',
          content: inputError,
          timestamp: new Date(),
          error: { type: 'validation', message: inputError },
        }
        setMessages(prev => [...prev, validationMessage])
        setIsLoading(false)
        return
      }
      for (const attachment of attachments) {
        const attachmentError = validateAttachment(attachment)
        if (attachmentError) {
          const validationMessage: Message = {
            id: uuidv4(),
            role: 'assistant',
            content: attachmentError,
            timestamp: new Date(),
            error: { type: 'validation', message: attachmentError },
          }
          setMessages(prev => [...prev, validationMessage])
          setIsLoading(false)
          return
        }
      }

      const data = await response.json()

      const sanitizeLLMOutput = (text: string): string => {
        if (typeof text !== 'string') return '';
        // Patterns for dynamic code execution primitives
        const dangerousPatterns = [
          /\beval\s*\(/gi,
          /\bexec\s*\(/gi,
          /\bnew\s+Function\s*\(/gi,
          /\bsetTimeout\s*\(\s*['"`]/gi,
          /\bsetInterval\s*\(\s*['"`]/gi,
          /\bsetImmediate\s*\(\s*['"`]/gi,
          /\bexecScript\s*\(/gi,
          /\bdocument\.write\s*\(/gi,
          /\bwindow\[\s*['"`]eval['"`]\s*\]/gi,
          /\bglobalThis\[\s*['"`]eval['"`]\s*\]/gi,
        ];
        let sanitized = text;
        for (const pattern of dangerousPatterns) {
          sanitized = sanitized.replace(pattern, (match) => `[BLOCKED:${match.replace(/[()]/g, '')}]`);
        }
        return sanitized;
      };

      if (!response.ok) {
        // Handle policy violations returned as errors
        const errorMessage: Message = {
          id: uuidv4(),
          role: 'assistant',
          content: data.detail || 'An error occurred',
          timestamp: new Date(),
          error: data.policy_error ? {
            type: data.policy_error.type,
            message: data.policy_error.message,
          } : undefined,
        }
        setMessages(prev => [...prev, errorMessage])
      } else {
        const generatedAt = data.generated_at ?? new Date().toISOString()
        const modelId = data.model_id ?? data.model ?? 'unknown'
        const watermark = data.watermark ?? `wp-${Buffer.from(`${modelId}:${generatedAt}`).toString('base64')}`
        const assistantMessage: Message = {
          id: uuidv4(),
          isSynthetic: true,
          modelId,
          generatedAt,
          watermark,
          role: 'assistant',
          content: sanitizeLLMOutput(data.response),
          timestamp: new Date(),
          error: data.policy_warning ? {
            type: data.policy_warning.type,
            message: data.policy_warning.message,
          } : undefined,
        }
        setMessages(prev => [...prev, assistantMessage])
      }
    } catch (error) {
      const errorMessage: Message = {
        id: uuidv4(),
        role: 'assistant',
        content: 'Failed to connect to the backend. Please ensure the server is running.',
        timestamp: new Date(),
        error: {
          type: 'general',
          message: 'Connection error',
        },
      }
      setMessages(prev => [...prev, errorMessage])
    } finally {
      setIsLoading(false)
    }
  }

  // --- Input sanitization and validation helpers ---
  const MAX_MESSAGE_LENGTH = 10000
  const ALLOWED_FILE_TYPES = [
    'image/png', 'image/jpeg', 'image/gif', 'image/webp',
    'application/pdf',
    'text/plain', 'text/html', 'text/csv',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  ]
  const MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024 // 10 MB

  const sanitizeTextInput = (text: string): string => {
    // Remove null bytes and non-printable control characters (except common whitespace)
    return text
      .replace(/\x00/g, '')                        // null bytes
      .replace(/[\x01-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '') // control chars except \t \n \r
      .trim()
  }

  const validateTextInput = (text: string): string | null => {
    if (!text || text.length === 0) return 'Message must not be empty.'
    if (text.length > MAX_MESSAGE_LENGTH)
      return `Message exceeds maximum allowed length of ${MAX_MESSAGE_LENGTH} characters.`
    return null
  }

  const validateAttachment = (attachment: { name: string; type: string; size?: number; content: string }): string | null => {
    if (!ALLOWED_FILE_TYPES.includes(attachment.type))
      return `File type "${attachment.type}" is not allowed for "${attachment.name}".`
    if (attachment.size !== undefined && attachment.size > MAX_FILE_SIZE_BYTES)
      return `File "${attachment.name}" exceeds the maximum allowed size of 10 MB.`
    // Validate base64 content for binary files
    if (attachment.type.startsWith('image/') || attachment.type === 'application/pdf') {
      if (!/^[A-Za-z0-9+/]*={0,2}$/.test(attachment.content))
        return `File "${attachment.name}" contains invalid base64 content.`
    }
    return null
  }
  // --- End sanitization helpers ---

  const readFileContent = (file: File): Promise<string> => {
    return new Promise((resolve, reject) => {
      const reader = new FileReader()
      reader.onload = () => {
        const result = reader.result as string
        // For binary files, return base64
        if (file.type.startsWith('image/') || file.type === 'application/pdf') {
          resolve(result.split(',')[1]) // Remove data URL prefix
        } else {
          resolve(result)
        }
      }
      reader.onerror = reject

      if (file.type.startsWith('image/') || file.type === 'application/pdf') {
        reader.readAsDataURL(file)
      } else {
        reader.readAsText(file)
      }
    })
  }

  const handleFileSelect = (files: File[]) => {
    setPendingFiles(prev => [...prev, ...files])
  }

  const removePendingFile = (index: number) => {
    setPendingFiles(prev => prev.filter((_, i) => i !== index))
  }

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      handleSubmit(e)
    }
  }

  return (
    <div className="flex flex-col h-screen">
      {/* Header */}
      <header className="flex items-center justify-center py-3 border-b border-chat-border bg-chat-sidebar">
        <h1 className="text-xl font-semibold text-white">PolicyProbe</h1>
      </header>

      {/* Messages Area */}
      <div className="flex-1 overflow-y-auto chat-scrollbar">
        {messages.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-gray-400">
            <div className="text-4xl mb-4">🔍</div>
            <h2 className="text-2xl font-medium text-white mb-2">PolicyProbe</h2>
            <p className="text-center max-w-md">
              Upload documents to analyze or ask questions about policy compliance.
              <br />
              <span className="text-sm text-gray-500 mt-2 block">
                Supports PDF, Word, HTML, and image files
              </span>
            </p>
          </div>
        ) : (
          <MessageList messages={messages} />
        )}
      </div>

      {/* File Upload Modal */}
      {showFileUpload && (
        <div className="border-t border-chat-border bg-chat-input p-4">
          <FileUpload onFilesSelected={handleFileSelect} />
        </div>
      )}

      {/* Pending Files Display */}
      {pendingFiles.length > 0 && (
        <div className="border-t border-chat-border bg-chat-input px-4 py-2">
          <div className="flex flex-wrap gap-2">
            {pendingFiles.map((file, index) => (
              <div
                key={index}
                className="flex items-center gap-2 bg-chat-hover rounded-lg px-3 py-1.5 text-sm"
              >
                <span className="text-gray-300">{file.name}</span>
                <button
                  onClick={() => removePendingFile(index)}
                  className="text-gray-500 hover:text-red-400"
                >
                  ×
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Input Area */}
      <div className="border-t border-chat-border bg-chat-bg p-4">
        <form onSubmit={handleSubmit} className="max-w-3xl mx-auto">
          <div className="relative flex items-end bg-chat-input rounded-xl border border-chat-border">
            {/* File Upload Button */}
            <button
              type="button"
              onClick={() => setShowFileUpload(!showFileUpload)}
              className="p-3 text-gray-400 hover:text-white transition-colors"
            >
              <Paperclip className="w-5 h-5" />
            </button>

            {/* Hidden file input */}
            <input
              ref={fileInputRef}
              type="file"
              multiple
              accept=".pdf,.doc,.docx,.html,.htm,.txt,.json,.jpg,.jpeg,.png"
              className="hidden"
              onChange={(e) => {
                if (e.target.files) {
                  handleFileSelect(Array.from(e.target.files))
                }
              }}
            />

            {/* Text Input */}
            <textarea
              ref={inputRef}
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="Message PolicyProbe..."
              className="flex-1 bg-transparent text-white placeholder-gray-500 resize-none py-3 pr-12 focus:outline-none max-h-48"
              rows={1}
              disabled={isLoading}
            />

            {/* Send Button */}
            <button
              type="submit"
              disabled={isLoading || (!input.trim() && pendingFiles.length === 0)}
              className="absolute right-2 bottom-2 p-2 text-gray-400 hover:text-white disabled:opacity-50 disabled:hover:text-gray-400 transition-colors"
            >
              {isLoading ? (
                <Loader2 className="w-5 h-5 animate-spin" />
              ) : (
                <Send className="w-5 h-5" />
              )}
            </button>
          </div>
          <p className="text-xs text-center text-gray-500 mt-2">
            PolicyProbe demonstrates AI policy evaluation and remediation
          </p>
        </form>
      </div>
    </div>
  )
}
