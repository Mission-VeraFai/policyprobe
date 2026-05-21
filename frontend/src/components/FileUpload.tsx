'use client'

import { useState, useCallback } from 'react'
import { Upload, FileText, Image, File } from 'lucide-react'

// Singapore PII patterns
const SG_PII_PATTERNS: { name: string; pattern: RegExp }[] = [
  // NRIC / FIN: S/T/F/G/M followed by 7 digits and a letter
  { name: 'NRIC/FIN', pattern: /\b[STFGM]\d{7}[A-Z]\b/i },
  // SingPass user ID format (NRIC-based, same pattern — covered above)
  // Singapore passport number: E followed by 7 digits
  { name: 'Singapore Passport', pattern: /\bE\d{7}[A-Z]\b/i },
  // Singapore phone numbers: +65 or 65 prefix with 8-digit local number
  { name: 'SG Phone', pattern: /(?:\+65|\b65)[ -]?[689]\d{3}[ -]?\d{4}\b/ },
  // Singapore postal code: 6-digit code (preceded by "Singapore" or "S(" to reduce false positives)
  { name: 'SG Postal Code', pattern: /\b(?:Singapore\s+|S\()\d{6}\b/i },
  // Full Name: common salutation + capitalised words (e.g. Mr John Tan)
  { name: 'Full Name', pattern: /\b(?:Mr|Mrs|Ms|Miss|Dr|Prof)\.?\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)+\b/ },
  // Date of Birth: common date formats (DD/MM/YYYY, DD-MM-YYYY, YYYY-MM-DD)
  { name: 'Date of Birth', pattern: /\b(?:dob|date\s+of\s+birth|born\s+on)[:\s]+\d{1,2}[\/-]\d{1,2}[\/-]\d{2,4}\b/i },
  // Generic date pattern near DOB keywords
  { name: 'Date (generic)', pattern: /\b(?:0?[1-9]|[12]\d|3[01])[\/-](?:0?[1-9]|1[0-2])[\/-](?:19|20)\d{2}\b/ },
  // Email address
  { name: 'Email', pattern: /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/ },
  // Singapore bank account numbers: DBS/POSB (10 digits), OCBC (9 digits), UOB (10 digits) — generic 9-12 digit sequences near bank keywords
  { name: 'Bank Account', pattern: /\b(?:account\s*(?:no|number|#)?[:\s]+)\d{9,12}\b/i },
  // CPF account / contribution references
  { name: 'CPF', pattern: /\b(?:cpf\s*(?:account|no|number|contribution)?[:\s]*)\d{7,9}[A-Z]?\b/i },
  // Health / medical record indicators
  { name: 'Health Record', pattern: /\b(?:diagnosis|medical\s+record|patient\s+id|prescription|medication|blood\s+type|allerg(?:y|ies))[:\s]+\S/i },
  // Race / ethnicity (PDPA sensitive category in Singapore)
  { name: 'Race/Ethnicity', pattern: /\b(?:race|ethnicity)[:\s]+(?:chinese|malay|indian|eurasian|others?)\b/i },
  // Religion (PDPA sensitive category)
  { name: 'Religion', pattern: /\b(?:religion|religious\s+belief)[:\s]+\S/i },
]

async function readFileAsText(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onload = () => resolve(reader.result as string)
    reader.onerror = () => reject(reader.error)
    reader.readAsText(file)
  })
}

const TEXT_READABLE_TYPES = [
  'text/plain',
  'text/html',
  'application/json',
]

async function containsSingaporePII(file: File): Promise<string | null> {
  // Only scan text-readable files; binary formats (PDF, DOC, images) would
  // require server-side extraction — flag them for server-side scanning instead.
  const isTextReadable =
    TEXT_READABLE_TYPES.includes(file.type) ||
    /\.(txt|html?|json)$/i.test(file.name)

  if (!isTextReadable) {
    // Binary files (PDF, DOC, images) cannot be scanned client-side and no
    // server-side scanning is implemented. Block them to prevent PII leakage.
    return 'binary file (cannot be scanned for PII — upload not permitted)'
  }

  let content: string
  try {
    content = await readFileAsText(file)
  } catch {
    // If we cannot read the file, err on the side of caution
    return 'unreadable file'
  }

  for (const { name, pattern } of SG_PII_PATTERNS) {
    if (pattern.test(content)) {
      return name
    }
  }

  return null
}

// Maximum allowed file size: 10 MB
const MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024

// Patterns indicative of prompt injection / hidden instructions
const PROMPT_INJECTION_PATTERNS: RegExp[] = [
  /ignore\s+(all\s+)?(previous|prior|above)\s+instructions/i,
  /disregard\s+(all\s+)?(previous|prior|above)\s+instructions/i,
  /forget\s+(all\s+)?(previous|prior|above)\s+instructions/i,
  /you\s+are\s+now\s+(a\s+)?(?!an?\s+assistant)/i,
  /act\s+as\s+(if\s+you\s+are\s+)?(?!an?\s+assistant)/i,
  /system\s*:\s*you\s+are/i,
  /<\s*system\s*>/i,
  /\[\s*system\s*\]/i,
  /###\s*instruction/i,
  /###\s*system/i,
  /jailbreak/i,
  /do\s+anything\s+now/i,
  /dan\s+mode/i,
  /developer\s+mode/i,
  // Hidden text via zero-width characters used to smuggle instructions
  /[\u200B-\u200D\uFEFF\u00AD]{3,}/,
  // Base64-encoded prompt injection (common obfuscation technique)
  /(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?/,
  // Leetspeak obfuscation of common injection phrases (e.g. 1gn0r3, d1sr3g4rd)
  /[i1][g9][n][o0][r][e3]\s+.{0,30}[i1][n][s5][t][r][u][c][t][i1][o0][n][s5]/i,
  /[d][i1][s5][r][e3][g9][a4][r][d]\s+.{0,30}[i1][n][s5][t][r][u][c][t][i1][o0][n][s5]/i,
  // Shell command injection patterns
  /(?:^|\s|;|\||&)(?:bash|sh|zsh|cmd|powershell|exec|eval|system|popen)\s*[\(\s]/im,
  // Command substitution and subshell patterns
  /(?:\$\(|`)[^)\`]{1,200}(?:\)|`)/,
  // Common shell operators used for command chaining
  /(?:&&|\|\||;;|\$\{IFS\})/,
  // Path traversal combined with executable references
  /(?:\.\.\/){2,}(?:bin|etc|usr|tmp)/i,
]

/**
 * Reads a text-based file and scans its content for prompt injection or
 * other malicious payload patterns.
 * Returns true if the content is considered safe, false otherwise.
 */
async function isContentSafe(file: File): Promise<boolean> {
  const textMimeTypes = [
    'text/plain',
    'text/html',
    'application/json',
  ]

  const textExtensions = ['.txt', '.html', '.htm', '.json']
  const lowerName = file.name.toLowerCase()

  const isTextFile =
    textMimeTypes.includes(file.type) ||
    textExtensions.some(ext => lowerName.endsWith(ext))

    if (!isTextFile) {
    // For binary formats, inspect magic bytes to reject known executable types
    // that could be used to smuggle malicious payloads.
    try {
      const MAGIC_BYTE_SLICE = 8
      const headerBuffer = await file.slice(0, MAGIC_BYTE_SLICE).arrayBuffer()
      const bytes = new Uint8Array(headerBuffer)
      const hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')
      // ELF executables: 7f454c46
      if (hex.startsWith('7f454c46')) {
        console.warn(`File "${file.name}" rejected: ELF executable detected`)
        return false
      }
      // Windows PE executables: 4d5a (MZ header)
      if (hex.startsWith('4d5a')) {
        console.warn(`File "${file.name}" rejected: PE executable detected`)
        return false
      }
      // Shell scripts starting with #! (shebang): 2321
      if (hex.startsWith('2321')) {
        console.warn(`File "${file.name}" rejected: shell script (shebang) detected`)
        return false
      }
    } catch {
      console.warn(`File "${file.name}" rejected: unable to inspect binary content`)
      return false
    }
    return true
  }" rejected: binary/non-text files are not permitted to prevent malicious content injection`
    )
    return false
  }

  try {
    const text = await file.text()
    for (const pattern of PROMPT_INJECTION_PATTERNS) {
      if (pattern.test(text)) {
        console.warn(
          `File "${file.name}" rejected: matched injection pattern ${pattern}`
        )
        return false
      }
    }
    return true
  } catch {
    // If we cannot read the file, reject it to be safe
    console.warn(`File "${file.name}" rejected: unable to read content`)
    return false
  }
}

/**
 * Validates a single file against size limits and content safety checks.
 */
async function isFileSafeForUpload(file: File): Promise<boolean> {
  if (file.size > MAX_FILE_SIZE_BYTES) {
    console.warn(
      `File "${file.name}" rejected: exceeds maximum size of ${MAX_FILE_SIZE_BYTES} bytes`
    )
    return false
  }

  if (file.size === 0) {
    console.warn(`File "${file.name}" rejected: empty file`)
    return false
  }

  return isContentSafe(file)
}

interface FileUploadProps {
  onFilesSelected: (files: File[]) => void
}

// PII patterns to detect and redact
const PII_PATTERNS: Array<{ pattern: RegExp; replacement: string }> = [
  // Email addresses
  { pattern: /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g, replacement: '[REDACTED_EMAIL]' },
  // US Social Security Numbers (XXX-XX-XXXX)
  { pattern: /\b\d{3}-\d{2}-\d{4}\b/g, replacement: '[REDACTED_SSN]' },
  // Credit card numbers (16 digits, optionally grouped)
  { pattern: /\b(?:\d[ \-]?){13,16}\b/g, replacement: '[REDACTED_CC]' },
  // US phone numbers
  { pattern: /\b(?:\+?1[\s.\-]?)?(?:\(?\d{3}\)?[\s.\-]?)\d{3}[\s.\-]?\d{4}\b/g, replacement: '[REDACTED_PHONE]' },
  // Names preceded by common titles
  { pattern: /\b(?:Mr|Mrs|Ms|Miss|Dr|Prof)\.?\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*/g, replacement: '[REDACTED_NAME]' },
  // IP addresses
  { pattern: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g, replacement: '[REDACTED_IP]' },
  // Dates of birth patterns (MM/DD/YYYY or YYYY-MM-DD)
  { pattern: /\b(?:0?[1-9]|1[0-2])\/(?:0?[1-9]|[12]\d|3[01])\/(?:19|20)\d{2}\b/g, replacement: '[REDACTED_DOB]' },
  { pattern: /\b(?:19|20)\d{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])\b/g, replacement: '[REDACTED_DOB]' },
]

const TEXT_MIME_TYPES = new Set([
  'text/plain',
  'text/html',
  'application/json',
])

async function redactPIIFromFile(file: File): Promise<File> {
  if (!TEXT_MIME_TYPES.has(file.type) && !file.name.match(/\.(txt|html?|json)$/i)) {
    // For binary files (PDF, DOC, images) that cannot be safely redacted client-side,
    // replace content with a notice so downstream processing is aware.
    const notice = `[FILE CONTENT REDACTED: Binary file "${file.name}" cannot be client-side PII-redacted. Please ensure server-side redaction is applied before use.]`
    return new File([notice], file.name, { type: 'text/plain', lastModified: file.lastModified })
  }

  const text = await file.text()
  let redacted = text
  for (const { pattern, replacement } of PII_PATTERNS) {
    redacted = redacted.replace(pattern, replacement)
  }
  return new File([redacted], file.name, { type: file.type, lastModified: file.lastModified })
}

export function FileUpload({ onFilesSelected }: FileUploadProps) {
  const [isDragOver, setIsDragOver] = useState(false)
  const [piiError, setPiiError] = useState<string | null>(null)

  const scanAndForward = useCallback(
    async (validFiles: File[]) => {
      setPiiError(null)
      const rejectedFiles: string[] = []

      const safeFiles = await Promise.all(
        validFiles.map(async (file) => {
          const piiType = await containsSingaporePII(file)
          if (piiType) {
            rejectedFiles.push(`${file.name} (detected: ${piiType})`)
            return null
          }
          return file
        })
      )

      if (rejectedFiles.length > 0) {
        setPiiError(
          `The following file(s) were rejected because they may contain Singapore PII: ${rejectedFiles.join(', ')}. Please remove sensitive information before uploading.`
        )
      }

      const approvedFiles = safeFiles.filter((f): f is File => f !== null)
      if (approvedFiles.length > 0) {
        onFilesSelected(approvedFiles)
      }
    },
    [onFilesSelected]
  )

    const handleDrop = useCallback(
    async (e: React.DragEvent<HTMLDivElement>) => {
      e.preventDefault()
      setIsDragOver(false)

            const files = Array.from(e.dataTransfer.files)
      const validFiles = files.filter(isValidFileType)

      if (validFiles.length > 0) {
        scanAndForward(validFiles)
      }
    },
    [onFilesSelected]
  ) => {
      e.preventDefault()
      setIsDragOver(false)

      const files = Array.from(e.dataTransfer.files)
      const typeValidFiles = files.filter(isValidFileType)

      const safetyResults = await Promise.all(
        typeValidFiles.map(isFileSafeForUpload)
      )
      const validFiles = typeValidFiles.filter((_, i) => safetyResults[i])

      if (validFiles.length > 0) {
        onFilesSelected(validFiles)
      }
    },
    [onFilesSelected]
  )

  const handleDragOver = useCallback((e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault()
    setIsDragOver(true)
  }, [])

  const handleDragLeave = useCallback((e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault()
    setIsDragOver(false)
  }, [])

    const handleFileInput = useCallback(
    async (e: React.ChangeEvent<HTMLInputElement>) => {
      if (e.target.files) {
                const files = Array.from(e.target.files)
        const validFiles = files.filter(isValidFileType)

        if (validFiles.length > 0) {
          scanAndForward(validFiles)
        }
      }
    },
    [onFilesSelected]
  ) => {
      if (e.target.files) {
        const files = Array.from(e.target.files)
        const typeValidFiles = files.filter(isValidFileType)

        const safetyResults = await Promise.all(
          typeValidFiles.map(isFileSafeForUpload)
        )
        const validFiles = typeValidFiles.filter((_, i) => safetyResults[i])

        if (validFiles.length > 0) {
          onFilesSelected(validFiles)
        }
      }
    },
    [onFilesSelected]
  )

  return (
    <div
      className={`file-upload-zone rounded-lg p-6 text-center cursor-pointer ${
        isDragOver ? 'drag-over' : ''
      }`}
      onDrop={handleDrop}
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
    >
      {piiError && (
        <div className="mb-3 rounded bg-red-900 px-4 py-2 text-sm text-red-200" role="alert">
          {piiError}
        </div>
      )}
      <input
        type="file"
        multiple
        accept=".pdf,.doc,.docx,.html,.htm,.txt,.json,.jpg,.jpeg,.png"
        className="hidden"
        id="file-upload-input"
        onChange={handleFileInput}
      />
      <label htmlFor="file-upload-input" className="cursor-pointer">
        <Upload className="w-10 h-10 text-gray-400 mx-auto mb-3" />
        <p className="text-gray-300 mb-2">
          Drag and drop files here, or click to browse
        </p>
        <div className="flex justify-center gap-4 text-xs text-gray-500">
          <div className="flex items-center gap-1">
            <FileText className="w-4 h-4" />
            <span>PDF, DOC, HTML</span>
          </div>
          <div className="flex items-center gap-1">
            <Image className="w-4 h-4" />
            <span>JPG, PNG</span>
          </div>
          <div className="flex items-center gap-1">
            <File className="w-4 h-4" />
            <span>TXT, JSON</span>
          </div>
        </div>
      </label>
    </div>
  )
}

function isValidFileType(file: File): boolean {
  const validTypes = [
    'application/pdf',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'text/html',
    'text/plain',
    'application/json',
    'image/jpeg',
    'image/png',
  ]

  const validExtensions = ['.pdf', '.doc', '.docx', '.html', '.htm', '.txt', '.json', '.jpg', '.jpeg', '.png']

  const hasValidType = validTypes.includes(file.type)
  const hasValidExtension = validExtensions.some(ext =>
    file.name.toLowerCase().endsWith(ext)
  )

  return hasValidType || hasValidExtension
}
