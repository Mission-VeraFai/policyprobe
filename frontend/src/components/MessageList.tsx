'use client'

import { Message } from './ChatInterface'
import { ErrorDisplay } from './ErrorDisplay'
import { User, Bot, Paperclip, AlertTriangle } from 'lucide-react'

// Patterns for dynamic code execution primitives that must never appear in LLM output
const DANGEROUS_PATTERNS: RegExp[] = [
  /\beval\s*\(/gi,
  /\bexec\s*\(/gi,
  /\bnew\s+Function\s*\(/gi,
  /\bsetTimeout\s*\(\s*['"`]/gi,
  /\bsetInterval\s*\(\s*['"`]/gi,
  /\bsetImmediate\s*\(\s*['"`]/gi,
  /\bexecScript\s*\(/gi,
  /\bdocument\.write\s*\(/gi,
  /\binnerHTML\s*=/gi,
  /\bouterHTML\s*=/gi,
  /\bimportScripts\s*\(/gi,
  /javascript\s*:/gi,
  /vbscript\s*:/gi,
  /data\s*:\s*text\/html/gi,
]

interface SanitizationResult {
  sanitized: string
  flagged: boolean
  detectedPatterns: string[]
}

// Singapore PII patterns
const SINGAPORE_PII_PATTERNS: { name: string; pattern: RegExp }[] = [
  { name: 'NRIC/FIN', pattern: /\b[STFGM]\d{7}[A-Z]\b/i },
  { name: 'SingPass', pattern: /\bsingpass\b/i },
  { name: 'Singapore Phone', pattern: /\b(\+65|65)?[689]\d{7}\b/ },
  { name: 'Singapore Postal Code', pattern: /\bSingapore\s+\d{6}\b/i },
]

function checkAttachmentForSingaporePII(attachment: { name: string; content?: string }): { hasPII: boolean; detectedTypes: string[] } {
  const detectedTypes: string[] = []
  const textToCheck = [attachment.name, attachment.content ?? ''].join(' ')
  for (const { name, pattern } of SINGAPORE_PII_PATTERNS) {
    pattern.lastIndex = 0
    if (pattern.test(textToCheck)) {
      detectedTypes.push(name)
    }
  }
  return { hasPII: detectedTypes.length > 0, detectedTypes }
}

function sanitizeLLMOutput(content: string): SanitizationResult {
  const detectedPatterns: string[] = []

  for (const pattern of DANGEROUS_PATTERNS) {
    // Reset lastIndex for global regexes
    pattern.lastIndex = 0
    if (pattern.test(content)) {
      detectedPatterns.push(pattern.source)
    }
  }

  if (detectedPatterns.length === 0) {
    return { sanitized: content, flagged: false, detectedPatterns: [] }
  }

  // Neutralize all dangerous patterns by inserting a zero-width space to break execution
  let sanitized = content
  for (const pattern of DANGEROUS_PATTERNS) {
    pattern.lastIndex = 0
    sanitized = sanitized.replace(pattern, (match) => `[BLOCKED:${match.trim()}]`)
  }

  return { sanitized, flagged: true, detectedPatterns }
}

// PII patterns to detect and redact from attachment metadata
const PII_PATTERNS: Array<{ pattern: RegExp; label: string }> = [
  { pattern: /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g, label: 'EMAIL' },
  { pattern: /\b(?:\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b/g, label: 'PHONE' },
  { pattern: /\b\d{3}-\d{2}-\d{4}\b/g, label: 'SSN' },
  { pattern: /\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13}|6(?:011|5\d{2})\d{12})\b/g, label: 'CC' },
]

function redactPIIFromFilename(filename: string): string {
  let redacted = filename
  for (const { pattern, label } of PII_PATTERNS) {
    pattern.lastIndex = 0
    redacted = redacted.replace(pattern, `[REDACTED-${label}]`)
  }
  return redacted
}

interface MessageListProps {
  messages: Message[]
}

export function MessageList({ messages }: MessageListProps) {
  return (
    <div className="flex flex-col">
      {messages.map((message) => (
        <div
          key={message.id}
          className={`py-6 ${
            message.role === 'assistant' ? 'bg-chat-hover' : ''
          }`}
        >
          <div className="max-w-3xl mx-auto px-4 flex gap-4">
            {/* Avatar */}
            <div
              className={`flex-shrink-0 w-8 h-8 rounded-sm flex items-center justify-center ${
                message.role === 'user'
                  ? 'bg-purple-600'
                  : 'bg-teal-600'
              }`}
            >
              {message.role === 'user' ? (
                <User className="w-5 h-5 text-white" />
              ) : (
                <Bot className="w-5 h-5 text-white" />
              )}
            </div>

            {/* Content */}
            <div className="flex-1 min-w-0">
              {/* Attachments */}
              {message.attachments && message.attachments.length > 0 && (
                <div className="flex flex-wrap gap-2 mb-3">
                  {message.attachments.map((attachment) => {
                    // Check the attachment name (and content if available) for malicious patterns
                    const nameCheck = sanitizeLLMOutput(attachment.name)
                    const contentCheck = attachment.content ? sanitizeLLMOutput(attachment.content) : { flagged: false, detectedPatterns: [] }
                    const isMalicious = nameCheck.flagged || contentCheck.flagged
                    const allDetected = [...nameCheck.detectedPatterns, ...contentCheck.detectedPatterns]

                    if (isMalicious) {
                      return (
                        <div
                          key={attachment.id}
                          className="flex items-center gap-2 bg-red-900 rounded-lg px-3 py-2 text-sm border border-red-700"
                          title={`Blocked: malicious content detected (${allDetected.join(', ')})`}
                        >
                          <Paperclip className="w-4 h-4 text-red-400" />
                          <span className="text-red-300">[ATTACHMENT BLOCKED: malicious content detected]</span>
                        </div>
                      )
                    }

                    return (
                      <div
                        key={attachment.id}
                        className="flex items-center gap-2 bg-chat-input rounded-lg px-3 py-2 text-sm border border-chat-border"
                      >
                        <Paperclip className="w-4 h-4 text-gray-400" />
                        <span className="text-gray-300">{nameCheck.sanitized}</span>
                        <span className="text-gray-500 text-xs">
                          ({formatFileSize(attachment.size)})
                        </span>
                      </div>
                    )
                  })}
                </div>
              )}

              {/* Message Content or Error */}
              {message.error ? (
                <ErrorDisplay error={message.error} />
              ) : (
                <div>
                  {message.role === 'assistant' && (
                    <div
                      className="flex items-center gap-2 mb-1"
                      data-provenance="ai-generated"
                      data-model="gpt-4o"
                      data-generated-at={message.timestamp.toISOString()}
                      aria-label="AI-generated content"
                    >
                      <span className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-xs font-medium bg-teal-900 text-teal-300 border border-teal-700">
                        <Bot className="w-3 h-3" />
                        AI-Generated
                      </span>
                                            <span className="text-xs text-gray-500" title="AI Assistant">
                        AI Assistant
                      </span>
                      <span className="text-xs text-gray-600" title="Generation timestamp">
                        &#x2022; {message.timestamp.toISOString()}
                      </span>
                    </div>
                  )}
                  {(() => {
                    const { sanitized, flagged, detectedPatterns } =
                      sanitizeLLMOutput(message.content)
                    return (
                      <>
                        {flagged && (
                          <div
                            className="flex items-center gap-2 mb-2 rounded px-2 py-1 text-xs font-medium bg-red-900 text-red-300 border border-red-700"
                            role="alert"
                            aria-label="Potentially unsafe content detected and blocked"
                          >
                            <AlertTriangle className="w-3 h-3 flex-shrink-0" />
                            <span>
                              Warning: Potentially unsafe content detected and neutralized
                              {process.env.NODE_ENV === 'development' && (
                                <> (patterns: {detectedPatterns.join(', ')})</>
                              )}
                            </span>
                          </div>
                        )}
                        <div
                          className="message-content text-gray-100 whitespace-pre-wrap"
                          aria-label={flagged ? 'Sanitized AI response' : 'AI response'}
                        >
                          {sanitized}
                        </div>
                      </>
                    )
                  })()}
                </div>
              )}

              {/* Timestamp */}
              <div className="text-xs text-gray-500 mt-2">
                {formatTime(message.timestamp)}
              </div>
            </div>
          </div>
        </div>
      ))}
    </div>
  )
}

function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

function formatTime(date: Date): string {
  return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
}
