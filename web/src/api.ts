export type Platform = 'chaoxing' | 'rainClassroom'
export type Server = 'yuketang' | 'pro' | 'changjiang' | 'huanghe'

export interface Account {
  id: string
  platform: Platform
  server: Server | ''
  name: string
  authorized: number
  valid: number
}

export interface Login {
  id: string
  platform: Platform
  server: Server | ''
  status: 'waiting' | 'success' | 'expired' | 'cancelled' | 'failed'
  message: string
  qr_image_url: string
  qr_content: string
  expires_at: number
  account_id: string | null
}

export interface Result {
  account_id: string
  name: string
  status: string
  message: string
  updated: number
}

export interface Job {
  id: string
  platform: Platform
  server: Server | ''
  status: 'running' | 'needs_action' | 'done'
  created_at: number
  is_initiator: boolean
  results: Result[]
}

export interface Me {
  csrf_token: string
  accounts: Account[]
  pool: { platform: Platform; server: Server | ''; count: number }[]
  jobs: Job[]
  logins: Login[]
}

export interface Challenge {
  id: string
  background: string
  piece: string
  width: number
  expires_at: number
}

export class ApiError extends Error {
  constructor(public status: number, message: string) { super(message) }
}

let csrf = ''
export function setCsrf(value: string) { csrf = value }

export async function api<T>(path: string, method = 'GET', body?: unknown): Promise<T> {
  let response: Response
  try {
    response = await fetch(`/api${path}`, {
      method,
      credentials: 'same-origin',
      headers: {
        Accept: 'application/json',
        ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
        ...(method !== 'GET' ? { 'X-CSRF-Token': csrf } : {}),
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    })
  } catch {
    throw new ApiError(0, '网络连接中断，请稍后重试；已提交的签到可能仍在执行。')
  }
  const data = await response.json().catch(() => ({}))
  if (!response.ok) {
    const detail = typeof data.detail === 'string' ? data.detail : '请求未能完成，请检查输入或稍后再试。'
    throw new ApiError(response.status, detail)
  }
  return data as T
}

export function subscribe<T>(path: string, snapshot: (data: T) => void, expired: () => void, interrupted: () => void) {
  const source = new EventSource(`/api${path}`)
  source.addEventListener('snapshot', (event) => snapshot(JSON.parse((event as MessageEvent).data) as T))
  source.addEventListener('auth_expired', () => { source.close(); expired() })
  source.onerror = interrupted
  return source
}
