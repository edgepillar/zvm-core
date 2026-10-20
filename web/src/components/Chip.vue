<script setup lang="ts">
// A status chip. Status never relies on colour alone: every tone that means
// something carries a dot, and the word is always there.
withDefaults(defineProps<{tone?: 'plain' | 'l2' | 'l1' | 'new' | 'warn' | 'bad'; title?: string; dot?: boolean}>(), {
  tone: 'plain',
  dot: false,
})

const tones: Record<string, {fg: string; bg: string; border: string}> = {
  plain: {fg: 'var(--dim)', bg: 'color-mix(in srgb, var(--line) 55%, transparent)', border: 'transparent'},
  l2: {fg: 'var(--znn-ink)', bg: 'color-mix(in srgb, var(--znn) 13%, transparent)', border: 'color-mix(in srgb, var(--znn) 26%, transparent)'},
  l1: {fg: 'var(--nom-ink)', bg: 'color-mix(in srgb, var(--nom-ink) 13%, transparent)', border: 'color-mix(in srgb, var(--nom-ink) 26%, transparent)'},
  new: {fg: 'var(--new-ink)', bg: 'color-mix(in srgb, var(--new) 13%, transparent)', border: 'color-mix(in srgb, var(--new) 26%, transparent)'},
  warn: {fg: 'var(--warn)', bg: 'color-mix(in srgb, var(--warn) 14%, transparent)', border: 'color-mix(in srgb, var(--warn) 28%, transparent)'},
  bad: {fg: 'var(--danger)', bg: 'color-mix(in srgb, var(--danger) 13%, transparent)', border: 'color-mix(in srgb, var(--danger) 28%, transparent)'},
}
</script>

<template>
  <span
    class="chip"
    :title="title"
    :style="{color: tones[tone].fg, background: tones[tone].bg, borderColor: tones[tone].border}"
  >
    <span v-if="dot" class="dot" :style="{background: tones[tone].fg}" />
    <slot />
  </span>
</template>
