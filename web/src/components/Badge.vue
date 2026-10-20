<script setup lang="ts">
// The system's tone names, mapped onto this app's structural ones. Kept as its
// own component because the mapping is a claim worth stating once: "info" here
// always means the NoM side, and "good" always means the ZVM executed it.
import {computed} from 'vue'
import Chip from './Chip.vue'

const props = withDefaults(
  defineProps<{tone?: 'plain' | 'good' | 'warn' | 'bad' | 'info' | 'accent'; title?: string}>(),
  {tone: 'plain'},
)

const MAP = {plain: 'plain', good: 'l2', warn: 'warn', bad: 'bad', info: 'l1', accent: 'new'} as const
const tone = computed(() => MAP[props.tone])
</script>

<template>
  <Chip :tone="tone" :title="title"><slot /></Chip>
</template>
