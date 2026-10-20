<script setup lang="ts">
// Zenoglyphs' "Rune Z": mitred joins, square caps, one weight, and a
// bind-stroke struck across the diagonal. Adopted verbatim from
// projects/zenoglyphs/web/ui/src/components/ZcribeMark.vue so the two surfaces
// carry the same mark rather than two drawings of it.
//
// The gradient is declared inline because an SVG stroke cannot reference a CSS
// variable, and the id is namespaced so a second copy on the page cannot
// collide with it.
withDefaults(defineProps<{size?: number}>(), {size: 24})
</script>

<template>
  <svg :width="size" :height="size" viewBox="0 0 24 24" fill="none" aria-hidden="true" class="shrink-0">
    <defs>
      <linearGradient id="zvm-rune-plasma" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="hsl(120 86% 63%)" />
        <stop offset="100%" stop-color="hsl(145 100% 38%)" />
      </linearGradient>
    </defs>
    <g stroke="url(#zvm-rune-plasma)" stroke-width="2.6" stroke-linecap="square" stroke-linejoin="miter">
      <path d="M5.3,5.3H18.7L5.3,18.7H18.7" />
      <path d="M9.6,9.6L14.4,14.4" />
    </g>
  </svg>
</template>
