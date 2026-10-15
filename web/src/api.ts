export type Platform = 'chaoxing' | 'rainClassroom'
export type Server = 'yuketang' | 'pro' | 'changjiang' | 'huanghe'

export interface Account {
  id: string
  platform: Platform
  server: Server | ''
  name: string
  valid: number
}

export interface GroupAccount {
  id: string
  platform: Platform
  server: Server | ''
  name: string
  active: boolean | number
}

export interface AccessCode {
  id: string
  code_hint: string
  status: 'available' | 'used' | 'legacy' | 'revoked'
  created_at: number
  used_at: number | null
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
  can_act: boolean
}

export interface JobSummary {
  total: number
  succeeded: number
  pending: number
  needs_action: number
}

export interface Job {
  id: string
  platform: Platform
  server: Server | ''
  status: 'running' | 'needs_action' | 'done'
  created_at: number
  is_initiator: boolean
  summary: JobSummary
  results: Result[]
}

export interface Me {
  csrf_token: string
  role: 'member' | 'admin'
  accounts: Account[]
  pool: { platform: Platform; server: Server | ''; count: number }[]
  logged_in_count: number
  group_accounts?: GroupAccount[]
  access_codes?: AccessCode[]
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

export interface Subscription { close(): void }

export function subscribe<T>(path: string, snapshot: (data: T) => void, expired: () => void, interrupted: () => void): Subscription {
  const resource = path.replace(/\/events$/, '')
  const interval = resource.startsWith('/logins/') ? 2500 : 15000
  let active = true
  let timer = 0

  const poll = async () => {
    try {
      const data = await api<T>(resource)
      snapshot(data)
      if (resource.startsWith('/logins/') && (data as Login).status !== 'waiting') {
        active = false
        return
      }
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) {
        active = false
        expired()
        return
      }
      interrupted()
    }
    if (active) timer = window.setTimeout(poll, interval)
  }

  void poll()
  return { close() { active = false; window.clearTimeout(timer) } }
}
