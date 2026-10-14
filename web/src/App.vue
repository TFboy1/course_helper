<script setup lang="ts">
import { computed, nextTick, onMounted, onUnmounted, ref } from 'vue'
import type { BrowserQRCodeReader, IScannerControls } from '@zxing/browser'
import CaptchaPanel from './CaptchaPanel.vue'
import { api, ApiError, setCsrf, subscribe } from './api'
import type { Account, Challenge, Job, Login, Me, Platform, Result, Server } from './api'

const serverNames: Record<Server, string> = { yuketang: '雨课堂', pro: '荷塘雨课堂', changjiang: '长江雨课堂', huanghe: '黄河雨课堂' }
const statusNames: Record<string, string> = {
  pending: '等待执行', running: '正在签到', success: '签到成功', already_signed: '已签到',
  needs_captcha: '待滑块验证', needs_official_verification: '待本人补验', session_expired: '登录失效',
  qr_expired: '二维码过期', failed: '未完成', unknown: '结果未确认', skipped: '已停止',
}
const me = ref<Me | null>(null)
const loading = ref(true)
const busy = ref('')
const joinCode = ref('')
const platform = ref<Platform>('chaoxing')
const server = ref<Server>('yuketang')
const notice = ref<{ text: string; error: boolean } | null>(null)
const pendingAccounts = ref(new Set<string>())
const loginDialog = ref<HTMLDialogElement | null>(null)
const activeLogin = ref<Login | null>(null)
const loginImage = ref('')
const qrText = ref('')
const cameraVisible = ref(false)
const cameraStarting = ref(false)
const video = ref<HTMLVideoElement | null>(null)
const fileInput = ref<HTMLInputElement | null>(null)
const selectedJob = ref('')
const currentJob = ref<Job | null>(null)
const streamHint = ref('')
const captchaDialog = ref<HTMLDialogElement | null>(null)
const challenge = ref<Challenge | null>(null)
const captchaTarget = ref<Result | null>(null)
const captchaBusy = ref(false)
let loginSource: EventSource | null = null
let meSource: EventSource | null = null
let cameraControls: IScannerControls | null = null
let cameraGeneration = 0
let submission: { input: string; id: string } | null = null

const currentPool = computed(() => me.value?.pool.find(p => p.platform === platform.value && p.server === (platform.value === 'rainClassroom' ? server.value : ''))?.count ?? 0)
const successCount = computed(() => currentJob.value?.results.filter(r => ['success', 'already_signed'].includes(r.status)).length ?? 0)
const actionCount = computed(() => currentJob.value?.results.filter(r => r.status.startsWith('needs_')).length ?? 0)
const progress = computed(() => !currentJob.value ? 0 : Math.round(currentJob.value.results.filter(r => !['pending', 'running'].includes(r.status)).length / currentJob.value.results.length * 100))

function label(p: Platform, s: Server | '') { return p === 'chaoxing' ? '学习通' : serverNames[s as Server] ?? '雨课堂' }
function timeLabel(timestamp: number) { return new Date(timestamp * 1000).toLocaleString('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' }) }
function flash(text: string, error = false) { notice.value = { text, error } }
function clearSession() {
  loginSource?.close(); meSource?.close(); meSource = null; stopCamera()
  loginDialog.value?.close(); captchaDialog.value?.close()
  activeLogin.value = null; currentJob.value = null; me.value = null; setCsrf('')
}
function handleError(error: unknown) {
  if (error instanceof ApiError && error.status === 401) clearSession()
  flash(error instanceof Error ? error.message : '操作未能完成，请稍后重试。', true)
}

function updateJob(job: Job) {
  const existing = me.value?.jobs.find(j => j.id === job.id)
  if (existing && Math.max(...existing.results.map(r => r.updated)) > Math.max(...job.results.map(r => r.updated))) job = existing
  if (me.value) {
    me.value.jobs = [job, ...me.value.jobs.filter(j => j.id !== job.id)].sort((a, b) => b.created_at - a.created_at).slice(0, 20)
  }
  if (selectedJob.value === job.id) currentJob.value = job
}

function selectJob(id: string) {
  selectedJob.value = id
  currentJob.value = me.value?.jobs.find(j => j.id === id) ?? null
  streamHint.value = ''
}

function acceptMe(data: Me) {
  const followingLatest = !selectedJob.value || selectedJob.value === me.value?.jobs[0]?.id
  if (followingLatest && data.jobs[0] && !captchaDialog.value?.open) selectedJob.value = data.jobs[0].id
  me.value = data; setCsrf(data.csrf_token)
  if (!selectedJob.value || !data.jobs.some(j => j.id === selectedJob.value)) selectedJob.value = data.jobs[0]?.id ?? ''
  selectJob(selectedJob.value)
}

async function refreshMe() {
  acceptMe(await api<Me>('/me'))
  if (!meSource) meSource = subscribe<Me>('/me/events', data => {
    streamHint.value = ''; acceptMe(data)
  }, () => { clearSession(); flash('网站会话已过期，请重新进入。', true) }, () => {
    streamHint.value = '进度连接正在恢复；也可以点击顶部刷新。'
  })
}

async function enter() {
  busy.value = 'access'
  try {
    const response = await api<{ csrf_token: string }>('/access', 'POST', { join_code: joinCode.value })
    setCsrf(response.csrf_token); joinCode.value = ''
    await refreshMe(); notice.value = null
  } catch (error) { handleError(error) }
  finally { busy.value = '' }
}

async function openLogin(login: Login) {
  activeLogin.value = login; loginImage.value = login.qr_image_url
  await nextTick()
  if (!loginDialog.value?.open) loginDialog.value?.showModal()
  if (login.qr_content) {
    try {
      const QRCode = (await import('qrcode')).default
      const image = await QRCode.toDataURL(login.qr_content, { width: 280, margin: 2, errorCorrectionLevel: 'M' })
      if (activeLogin.value?.id === login.id) loginImage.value = image
    } catch { if (!loginImage.value) flash('登录二维码生成失败，请重新生成。', true) }
  }
  loginSource?.close()
  loginSource = subscribe<Login>(`/logins/${login.id}/events`, async data => {
    if (activeLogin.value?.id !== data.id) return
    activeLogin.value = data
    if (data.status !== 'waiting') { loginSource?.close(); loginSource = null }
    if (data.status === 'success') {
      loginDialog.value?.close(); activeLogin.value = null
      flash('登录成功。开启账号授权后，就能参与批量签到。')
      try { await refreshMe() } catch (error) { handleError(error) }
    }
  }, () => { clearSession(); flash('网站会话已过期，请重新进入。', true) }, () => {
    if (activeLogin.value?.status === 'waiting') activeLogin.value.message = '连接正在恢复，请保留二维码或稍后刷新。'
  })
}

async function startLogin() {
  busy.value = 'login'
  try {
    if (activeLogin.value?.status === 'waiting') await api(`/logins/${activeLogin.value.id}`, 'DELETE')
    const login = await api<Login>('/logins', 'POST', { platform: platform.value, ...(platform.value === 'rainClassroom' ? { server: server.value } : {}) })
    await openLogin(login)
  } catch (error) { handleError(error) }
  finally { busy.value = '' }
}

async function closeLogin() {
  const login = activeLogin.value
  loginSource?.close(); loginSource = null; activeLogin.value = null; loginDialog.value?.close()
  if (login?.status === 'waiting') {
    try { await api(`/logins/${login.id}`, 'DELETE') } catch (error) { handleError(error) }
  }
}

async function toggleAuthorization(account: Account, event: Event) {
  const input = event.target as HTMLInputElement
  pendingAccounts.value.add(account.id)
  try {
    await api(`/accounts/${account.id}/authorization`, 'PATCH', { enabled: input.checked })
    await refreshMe(); flash(input.checked ? `${account.name} 已加入共享授权池。` : `${account.name} 已停止参与新的批量签到。`)
  } catch (error) { input.checked = Boolean(account.authorized); handleError(error) }
  finally { pendingAccounts.value.delete(account.id) }
}

async function unbind(account: Account) {
  if (!window.confirm(`解绑 ${account.name} 会撤销授权并删除保存的登录态，重新使用需要扫码登录。确认解绑？`)) return
  pendingAccounts.value.add(account.id)
  try { await api(`/accounts/${account.id}`, 'DELETE'); await refreshMe(); flash('账号已解绑，授权已撤销。') }
  catch (error) { handleError(error) }
  finally { pendingAccounts.value.delete(account.id) }
}

async function logout() {
  if (!window.confirm('退出网站后，已授权账号仍可参与签到。若希望停止，请先关闭账号授权。现在退出网站？')) return
  try { await api('/access', 'DELETE'); clearSession(); flash('已退出网站，已授予的签到授权保留。') }
  catch (error) { handleError(error) }
}

async function submitQr(value = qrText.value) {
  const input = value.trim()
  if (!input || busy.value === 'sign') return
  stopCamera(); qrText.value = input; busy.value = 'sign'
  if (!submission || submission.input !== input) submission = { input, id: crypto.randomUUID() }
  try {
    const job = await api<Job>('/sign-jobs', 'POST', { qr_text: input, request_id: submission.id })
    submission = null; platform.value = job.platform
    if (job.server) server.value = job.server
    updateJob(job); selectedJob.value = job.id; selectJob(job.id)
    flash('签到已发起，可以在下面查看每个账号的结果。')
  } catch (error) { handleError(error) }
  finally { busy.value = '' }
}

async function newReader(): Promise<BrowserQRCodeReader> {
  const { BrowserQRCodeReader } = await import('@zxing/browser')
  return new BrowserQRCodeReader()
}
function stopCamera() {
  cameraGeneration++; cameraControls?.stop(); cameraControls = null
  cameraVisible.value = false; cameraStarting.value = false
}
async function startCamera() {
  if (!window.isSecureContext || !navigator.mediaDevices?.getUserMedia) {
    flash('摄像头需要 HTTPS 或 localhost。你也可以上传二维码图片或粘贴链接。', true); return
  }
  stopCamera(); const generation = ++cameraGeneration
  cameraVisible.value = true; cameraStarting.value = true
  await nextTick()
  try {
    const reader = await newReader()
    if (!video.value || generation !== cameraGeneration) return
    let handled = false
    const controls = await reader.decodeFromConstraints({ video: { facingMode: { ideal: 'environment' } }, audio: false }, video.value, (result, _error, activeControls) => {
      if (result && !handled && generation === cameraGeneration) {
        handled = true; activeControls.stop(); void submitQr(result.getText())
      }
    })
    if (generation !== cameraGeneration || handled) controls.stop()
    else { cameraControls = controls; cameraStarting.value = false }
  } catch {
    if (generation === cameraGeneration) { stopCamera(); flash('摄像头未能打开，请检查权限，或改用上传图片。', true) }
  }
}

async function decodeFile(event: Event) {
  const input = event.target as HTMLInputElement
  const file = input.files?.[0]
  if (!file) return
  if (!file.type.startsWith('image/') || file.size > 10 * 1024 * 1024) { flash('请选择小于 10 MB 的二维码图片。', true); input.value = ''; return }
  busy.value = 'image'
  const url = URL.createObjectURL(file)
  try { const reader = await newReader(); const result = await reader.decodeFromImageUrl(url); await submitQr(result.getText()) }
  catch (error) { if (error instanceof ApiError) handleError(error); else flash('图片中没有识别到二维码，请上传清晰、完整的图片。', true) }
  finally { URL.revokeObjectURL(url); input.value = ''; if (busy.value === 'image') busy.value = '' }
}

async function loadCaptcha(result = captchaTarget.value) {
  if (!result || !currentJob.value) return
  captchaTarget.value = result; captchaBusy.value = true
  try {
    challenge.value = await api<Challenge>(`/sign-jobs/${currentJob.value.id}/accounts/${result.account_id}/captcha`, 'POST', {})
    await nextTick(); if (!captchaDialog.value?.open) captchaDialog.value?.showModal()
  } catch (error) { handleError(error) }
  finally { captchaBusy.value = false }
}
async function verifyCaptcha(x: number) {
  if (!currentJob.value || !captchaTarget.value || !challenge.value) return
  captchaBusy.value = true
  try {
    const job = await api<Job>(`/sign-jobs/${currentJob.value.id}/accounts/${captchaTarget.value.account_id}/captcha/verify`, 'POST', { challenge_id: challenge.value.id, x })
    updateJob(job); captchaDialog.value?.close(); challenge.value = null
    flash('补验请求已处理，请查看账号结果。')
    if (job.status !== 'done') selectJob(job.id)
  } catch (error) { handleError(error) }
  finally { captchaBusy.value = false }
}
async function refreshReceipt(result: Result) {
  if (!currentJob.value) return
  pendingAccounts.value.add(result.account_id)
  try {
    const response = await api<{ message: string; job: Job }>(`/sign-jobs/${currentJob.value.id}/accounts/${result.account_id}/receipt`, 'POST', {})
    updateJob(response.job); flash(response.message)
  } catch (error) { handleError(error) }
  finally { pendingAccounts.value.delete(result.account_id) }
}
async function refresh() { try { await refreshMe() } catch (error) { handleError(error) } }
function visibleAgain() { if (document.visibilityState === 'visible' && me.value) void refresh() }

onMounted(async () => {
  try {
    await refreshMe()
    if (me.value?.accounts[0]) { platform.value = me.value.accounts[0].platform; if (me.value.accounts[0].server) server.value = me.value.accounts[0].server }
    if (me.value?.logins[0]) await openLogin(me.value.logins[0])
  } catch (error) { if (!(error instanceof ApiError && error.status === 401)) handleError(error) }
  finally { loading.value = false }
  document.addEventListener('visibilitychange', visibleAgain)
})
onUnmounted(() => { loginSource?.close(); meSource?.close(); stopCamera(); document.removeEventListener('visibilitychange', visibleAgain) })
</script>

<template>
  <div class="page-shell">
    <header class="masthead">
      <a class="brand" href="/" aria-label="课程助手首页"><span class="brand-mark" aria-hidden="true">课</span><span>课程助手<small>共享签到工作台</small></span></a>
      <div v-if="me" class="header-actions"><button class="text-button" type="button" @click="refresh">刷新</button><span aria-hidden="true">/</span><button class="text-button" type="button" @click="logout">退出网站</button></div>
      <span v-else class="private-label"><span class="dot"></span> 受邀成员使用</span>
    </header>

    <div v-if="notice" :class="['notice', { error: notice.error }]" :role="notice.error ? 'alert' : 'status'" aria-live="polite"><span>{{ notice.text }}</span><button type="button" aria-label="关闭提示" @click="notice = null">×</button></div>

    <main v-if="loading" class="loading-state" role="status"><span class="spinner"></span>正在恢复会话…</main>
    <main v-else-if="!me" class="welcome">
      <section class="welcome-copy">
        <p class="eyebrow">少一步操作，多一份从容</p>
        <h1>有人扫码，<br />大家一起完成。</h1>
        <p class="welcome-description">登录自己的学习平台账号，开启授权。下一次签到，交给正在扫码的那位同学。</p>
        <div class="welcome-steps"><span><b>01</b> 进入</span><span><b>02</b> 登录与授权</span><span><b>03</b> 共享签到</span></div>
      </section>
      <section class="entry-card">
        <div class="section-number" aria-hidden="true">01 / 进入工作台</div>
        <h2>从一个加入码开始</h2><p class="muted">向邀请你的人获取加入码。</p>
        <form @submit.prevent="enter"><label for="join-code">加入码</label><input id="join-code" v-model="joinCode" type="password" maxlength="256" autocomplete="off" placeholder="输入加入码" required /><button class="button primary full" type="submit" :disabled="!!busy">{{ busy === 'access' ? '正在进入…' : '进入工作台 →' }}</button></form>
        <p class="fine-print">无需另注册网站账号。进入后，用学习通或雨课堂官方 App 扫码登录。</p>
      </section>
    </main>

    <main v-else class="workspace">
      <section class="workspace-intro"><div><p class="eyebrow">你的小组，今天也在一起</p><h1>把签到交给一次扫码。</h1></div><div class="pool-summary"><b>{{ currentPool.toString().padStart(2, '0') }}</b><span>{{ label(platform, platform === 'chaoxing' ? '' : server) }}<br />有效授权账号</span></div></section>
      <div class="workspace-grid">
        <section class="panel account-panel">
          <div class="panel-heading"><div><p class="section-number">01 / 我的账号</p><h2>登录，然后选择授权</h2></div><span class="small-count">{{ me.accounts.length }} 个</span></div>
          <div class="platform-tabs" aria-label="选择登录平台"><button type="button" :class="{ selected: platform === 'chaoxing' }" @click="platform = 'chaoxing'">学习通</button><button type="button" :class="{ selected: platform === 'rainClassroom' }" @click="platform = 'rainClassroom'">雨课堂</button></div>
          <div class="login-controls"><label v-if="platform === 'rainClassroom'" class="server-picker">服务器<select v-model="server"><option v-for="(name, key) in serverNames" :key="key" :value="key">{{ name }}</option></select></label><button class="button secondary" type="button" :disabled="!!busy" @click="startLogin">{{ busy === 'login' ? '正在获取二维码…' : `扫码登录${label(platform, platform === 'chaoxing' ? '' : server)}` }} <span aria-hidden="true">↗</span></button></div>
          <div v-if="!me.accounts.length" class="empty-accounts"><span class="empty-symbol" aria-hidden="true">＋</span><h3>先登录你的第一个账号</h3><p>账号验证成功后，会出现在这里。</p></div>
          <ul v-else class="account-list"><li v-for="account in me.accounts" :key="account.id"><div class="account-top"><span class="avatar" aria-hidden="true">{{ account.name.slice(0, 1) }}</span><div class="account-name"><b>{{ account.name }}</b><span>{{ label(account.platform, account.server) }}</span></div><span :class="['badge', account.valid ? 'valid' : 'warning']">{{ account.valid ? '已登录' : '需重新登录' }}</span></div><div class="account-bottom"><label class="authorization"><input type="checkbox" :checked="!!account.authorized" :disabled="(!account.valid && !account.authorized) || pendingAccounts.has(account.id)" @change="toggleAuthorization(account, $event)" /><span>{{ account.authorized ? '已授权参与批量签到' : '允许参与批量签到' }}</span></label><button class="text-button danger" type="button" :disabled="pendingAccounts.has(account.id)" @click="unbind(account)">解绑</button></div></li></ul>
          <div class="authorization-note"><span aria-hidden="true">↳</span><p>授权后，本网站其他已登录成员可以为你发起签到。关闭网页或退出网站仍可参与；关闭授权可停止新的请求。</p></div>
        </section>

        <div class="right-column">
          <section class="panel scan-panel"><div class="panel-heading"><div><p class="section-number">02 / 发起签到</p><h2>一张二维码，一起签到</h2></div><span class="scan-glyph" aria-hidden="true">⌗</span></div><p class="muted">自动识别两平台的签到码，为对应平台与服务器的授权账号发起签到。</p><div class="scan-actions"><button class="button primary" type="button" :disabled="!!busy || cameraStarting" @click="startCamera">{{ cameraStarting ? '正在打开摄像头…' : '打开摄像头扫码' }}</button><button class="button ghost" type="button" :disabled="!!busy" @click="fileInput?.click()">{{ busy === 'image' ? '正在识别…' : '上传二维码图片' }}</button><input ref="fileInput" class="sr-only" type="file" accept="image/*" aria-label="上传二维码图片" @change="decodeFile" /></div><div v-if="cameraVisible" class="camera-panel"><video ref="video" autoplay muted playsinline aria-label="二维码摄像头预览"></video><div class="camera-target" aria-hidden="true"></div><button class="button camera-close" type="button" @click="stopCamera">关闭摄像头</button></div><form class="link-form" @submit.prevent="submitQr()"><label for="qr-link">或粘贴签到二维码链接</label><textarea id="qr-link" v-model="qrText" rows="2" maxlength="8192" placeholder="https://…" required></textarea><button class="button submit-link" type="submit" :disabled="!!busy || !qrText.trim()">{{ busy === 'sign' ? '正在发起…' : '发起批量签到 →' }}</button></form></section>

          <section class="panel result-panel"><div class="panel-heading"><div><p class="section-number">03 / 签到结果</p><h2>每个人，都有结果</h2></div><span v-if="currentJob" :class="['badge', currentJob.status === 'done' ? 'valid' : 'warning']">{{ currentJob.status === 'running' ? '执行中' : currentJob.status === 'needs_action' ? '待补验' : '已处理' }}</span></div><label v-if="me.jobs.length" class="job-picker">签到记录<select v-model="selectedJob" @change="selectJob(selectedJob)"><option v-for="job in me.jobs" :key="job.id" :value="job.id">{{ timeLabel(job.created_at) }} · {{ label(job.platform, job.server) }}{{ job.is_initiator ? ' · 我发起的' : ' · 我的结果' }}</option></select></label><div v-if="!currentJob" class="empty-results"><span aria-hidden="true">—</span><p>第一次扫码之后，结果会出现在这里。</p></div><template v-else><div class="result-summary"><span><strong>{{ successCount }}</strong> / {{ currentJob.results.length }} 已签到</span><span v-if="actionCount" class="action-count">{{ actionCount }} 个待补验</span><span v-else class="muted">{{ timeLabel(currentJob.created_at) }}</span></div><div class="progress-track" role="progressbar" :aria-valuenow="progress" aria-valuemin="0" aria-valuemax="100" aria-label="账号处理进度"><span :style="{ width: `${progress}%` }"></span></div><p v-if="streamHint" class="fine-print" role="status">{{ streamHint }}</p><ul class="result-list"><li v-for="result in currentJob.results" :key="result.account_id"><div class="result-main"><b>{{ result.name }}</b><span :class="['result-status', { good: ['success', 'already_signed'].includes(result.status), caution: result.status.startsWith('needs_') || result.status === 'unknown' }]"><span v-if="result.status === 'running'" class="spinner small"></span>{{ statusNames[result.status] ?? '待确认' }}</span></div><p>{{ result.message }}</p><div v-if="result.status === 'needs_captcha' || (currentJob.platform === 'chaoxing' && ['needs_official_verification', 'unknown', 'failed', 'qr_expired'].includes(result.status))" class="result-actions"><button v-if="result.status === 'needs_captcha'" class="text-button" type="button" :disabled="captchaBusy" @click="loadCaptcha(result)">完成滑块验证 ↗</button><button v-if="currentJob.platform === 'chaoxing'" class="text-button" type="button" :disabled="pendingAccounts.has(result.account_id)" @click="refreshReceipt(result)">刷新官方回执</button></div></li></ul><p v-if="currentJob.platform === 'rainClassroom' && currentJob.results.some(r => r.status === 'unknown')" class="fine-print">雨课堂未确认的结果请在官方 App 核实，网站不会自动重复提交。</p></template></section>
        </div>
      </div>
    </main>

    <footer class="footer"><span>课程助手</span><span>一人扫码 · 按授权执行 · 随时撤销</span></footer>
    <dialog ref="loginDialog" class="modal login-modal" @cancel.prevent="closeLogin"><button class="modal-close" type="button" aria-label="关闭登录二维码" @click="closeLogin">×</button><template v-if="activeLogin"><p class="eyebrow">{{ label(activeLogin.platform, activeLogin.server) }}</p><h2>用官方 App 扫码登录</h2><p class="muted">打开{{ activeLogin.platform === 'chaoxing' ? '学习通' : '雨课堂' }}，扫描二维码并确认授权。</p><div class="login-qr"><img v-if="activeLogin.status === 'waiting' && loginImage" :src="loginImage" alt="请用对应官方 App 扫描的登录二维码" /><div v-else class="qr-expired"><span aria-hidden="true">↻</span><p>{{ activeLogin.message || '二维码已失效' }}</p></div></div><p class="login-status" role="status">{{ activeLogin.message || '正在等待官方 App 确认…' }}</p><button class="button secondary full" type="button" :disabled="!!busy" @click="startLogin">重新生成二维码</button><p class="fine-print">官方 App 支持相册识别时，可以保存二维码后在相册中选择。</p></template></dialog>
    <dialog ref="captchaDialog" class="modal captcha-modal" @cancel="challenge = null"><button class="modal-close" type="button" aria-label="关闭滑块验证" :disabled="captchaBusy" @click="captchaDialog?.close(); challenge = null">×</button><CaptchaPanel v-if="challenge && captchaTarget" :challenge="challenge" :name="captchaTarget.name" :busy="captchaBusy" @verify="verifyCaptcha" @refresh="loadCaptcha()" /></dialog>
  </div>
</template>
