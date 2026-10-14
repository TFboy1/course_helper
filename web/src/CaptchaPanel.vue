<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import type { Challenge } from './api'

const props = defineProps<{ challenge: Challenge; name: string; busy: boolean }>()
const emit = defineEmits<{ verify: [x: number]; refresh: [] }>()
const position = ref(0)
const imageError = ref(false)
watch(() => props.challenge.id, () => { position.value = 0; imageError.value = false })
// 对应 Flutter CaptchaPage 的 320×160 设计稿与 280/264 坐标映射。
const x = computed(() => (position.value / 100 * 280 - 8) * props.challenge.width / 320)
</script>

<template>
  <div class="captcha-panel">
    <p class="eyebrow">人工补验</p>
    <h2>{{ name }} 的滑块验证</h2>
    <p class="muted">拖动下方滑块，让拼图与缺口重合，再提交验证。</p>
    <div v-if="!imageError" class="captcha-picture">
      <img :src="challenge.background" alt="验证码背景，含需要匹配的缺口" @error="imageError = true" />
      <img class="captcha-piece" :style="{ left: `${position * 0.825}%` }" :src="challenge.piece" alt="可移动的拼图" @error="imageError = true" />
    </div>
    <p v-else class="inline-error" role="alert">图片未能加载，请刷新验证码。</p>
    <label class="sr-only" for="captcha-position">移动拼图位置</label>
    <input id="captcha-position" v-model.number="position" class="captcha-range" type="range" min="0" max="100" step="0.1" :disabled="busy || imageError" />
    <div class="dialog-actions">
      <button class="button ghost" type="button" :disabled="busy" @click="emit('refresh')">换一张</button>
      <button class="button primary" type="button" :disabled="busy || imageError || x <= 0" @click="emit('verify', x)">{{ busy ? '正在验证…' : '提交验证' }}</button>
    </div>
  </div>
</template>
