<script setup lang="ts">
// A still lattice of dots behind the page. The pointer lights the ones it
// passes over; nothing else about it moves.
//
// This replaces the soft blob that used to follow the cursor. The blob was
// light with nothing to fall on, so it read as a smudge over the page; here the
// same pointer position is spent on the only thing in the background that can
// show it: the dots themselves. The grid never drifts, rotates or breathes, so
// a still screenshot of any page looks exactly like the page at rest.
//
// The lattice itself is painted once into an offscreen canvas and blitted each
// frame, so a frame costs one full-screen draw plus one arc per *lit* dot,
// a couple of hundred at most, rather than an arc for every dot on screen.
//
// Nothing here is reactive. A pointermove handler that wrote to reactive state
// would re-run every binding on the page sixty times a second for decoration.
import {onMounted, onUnmounted, ref} from 'vue'

const el = ref<HTMLCanvasElement | null>(null)

/** Distance between neighbouring dots, in CSS pixels. Tight enough that the
 *  lit patch is a shape rather than a handful of points, loose enough that the
 *  resting lattice stays texture and never becomes a surface. */
const SPACING = 26
/** How far the pointer's light reaches. */
const REACH = 150
/** Per-frame approach rates. Lighting is close to immediate so a dot answers
 *  the pointer, fading is slow so the path taken stays visible for a moment
 *  behind it, and that trail is the whole effect. */
const RISE = 0.34
const FALL = 0.055
/** Below this a dot is off: it stops being drawn and leaves the active set. */
const CUTOFF = 0.004

// A touch screen has no hovering pointer, and a lattice lit wherever a finger
// last tapped is worse than one that is evenly dark.
const fine = typeof window !== 'undefined' && window.matchMedia('(pointer: fine)').matches

let ctx: CanvasRenderingContext2D | null = null
let base: HTMLCanvasElement | null = null
let width = 0
let height = 0
let dpr = 1
let cols = 0
let rows = 0
let originX = 0
let originY = 0
let dimColor = '#2b3a40'
let litColor = '#21e575'

/** Dot index -> current brightness, for the dots that are not fully dark.
 *  Keyed by `row * cols + col`; every other dot is known to be at 0 and costs
 *  nothing per frame. */
const active = new Map<number, number>()
let pointerX = -1e6
let pointerY = -1e6
let inside = false
let frame = 0

function readColors(): void {
  const style = getComputedStyle(document.documentElement)
  dimColor = style.getPropertyValue('--line-strong').trim() || dimColor
  litColor = style.getPropertyValue('--znn-ink').trim() || litColor
}

/** Repaints the resting lattice. Called on resize and on a theme change, not
 *  per frame. */
function drawBase(): void {
  if (!base) return
  const bctx = base.getContext('2d')
  if (!bctx) return
  base.width = Math.max(1, Math.round(width * dpr))
  base.height = Math.max(1, Math.round(height * dpr))
  bctx.setTransform(dpr, 0, 0, dpr, 0, 0)
  bctx.clearRect(0, 0, width, height)
  bctx.fillStyle = dimColor
  bctx.globalAlpha = 0.7
  bctx.beginPath()
  for (let row = 0; row < rows; row++) {
    const y = originY + row * SPACING
    for (let col = 0; col < cols; col++) {
      const x = originX + col * SPACING
      bctx.moveTo(x + 1.1, y)
      bctx.arc(x, y, 1.1, 0, Math.PI * 2)
    }
  }
  bctx.fill()
}

function resize(): void {
  const canvas = el.value
  if (!canvas || !ctx) return
  width = window.innerWidth
  height = window.innerHeight
  dpr = Math.min(window.devicePixelRatio || 1, 2)
  canvas.width = Math.max(1, Math.round(width * dpr))
  canvas.height = Math.max(1, Math.round(height * dpr))
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
  cols = Math.floor(width / SPACING) + 1
  rows = Math.floor(height / SPACING) + 1
  // Centre the grid rather than hanging it off the top-left, so the margin at
  // the right and bottom edges matches the one at the left and top at any
  // window size.
  originX = (width - (cols - 1) * SPACING) / 2
  originY = (height - (rows - 1) * SPACING) / 2
  drawBase()
  draw()
}

/** Marks every dot within reach of the pointer as wanting to be lit. Only this
 *  neighbourhood is scanned; dots outside it are already in `active` if they
 *  are still fading, and at 0 otherwise. */
function light(): void {
  if (!inside) return
  const c0 = Math.max(0, Math.floor((pointerX - REACH - originX) / SPACING))
  const c1 = Math.min(cols - 1, Math.ceil((pointerX + REACH - originX) / SPACING))
  const r0 = Math.max(0, Math.floor((pointerY - REACH - originY) / SPACING))
  const r1 = Math.min(rows - 1, Math.ceil((pointerY + REACH - originY) / SPACING))
  for (let row = r0; row <= r1; row++) {
    const dy = originY + row * SPACING - pointerY
    for (let col = c0; col <= c1; col++) {
      const dx = originX + col * SPACING - pointerX
      const d = Math.sqrt(dx * dx + dy * dy)
      if (d > REACH) continue
      const key = row * cols + col
      // Brightest at the pointer, gone at the rim, with the falloff squared so
      // the centre of the patch is distinct instead of the whole disc reading
      // as one even wash.
      const target = (1 - d / REACH) ** 2
      const current = active.get(key) ?? 0
      active.set(key, current + (target - current) * RISE)
    }
  }
}

function draw(): void {
  if (!ctx || !base) return
  ctx.clearRect(0, 0, width, height)
  ctx.drawImage(base, 0, 0, width, height)
  ctx.fillStyle = litColor
  for (const [key, value] of active) {
    const x = originX + (key % cols) * SPACING
    const y = originY + Math.floor(key / cols) * SPACING
    // A halo under the core: a dot that only changes colour reads as a state
    // flag, one that also gains a little light around it reads as lit.
    ctx.globalAlpha = value * 0.16
    ctx.beginPath()
    ctx.arc(x, y, 5.5, 0, Math.PI * 2)
    ctx.fill()
    ctx.globalAlpha = Math.min(1, value)
    ctx.beginPath()
    ctx.arc(x, y, 1.1 + value * 1.1, 0, Math.PI * 2)
    ctx.fill()
  }
  ctx.globalAlpha = 1
}

function tick(): void {
  frame = 0
  // Dots the pointer has left behind decay towards dark; the ones under it are
  // then raised again by light(), so a dot inside the reach settles at its
  // distance's brightness instead of ratcheting between the two.
  for (const [key, value] of active) {
    const next = value + (0 - value) * FALL
    if (next < CUTOFF) active.delete(key)
    else active.set(key, next)
  }
  light()
  draw()
  // The loop only exists while there is something to settle. With the pointer
  // off the window and the last dot dark, the background costs nothing at all.
  if (active.size > 0 || inside) frame = requestAnimationFrame(tick)
}

function wake(): void {
  if (!frame) frame = requestAnimationFrame(tick)
}

function onMove(event: PointerEvent): void {
  pointerX = event.clientX
  pointerY = event.clientY
  inside = true
  wake()
}

function onLeave(): void {
  inside = false
  wake()
}

let observer: MutationObserver | null = null

onMounted(() => {
  if (!fine) return
  const canvas = el.value
  if (!canvas) return
  ctx = canvas.getContext('2d')
  if (!ctx) return
  base = document.createElement('canvas')
  readColors()
  resize()
  window.addEventListener('resize', resize)
  window.addEventListener('pointermove', onMove, {passive: true})
  document.addEventListener('pointerleave', onLeave)
  // The palette flips with the theme toggle, and the resting lattice is a
  // cached image that would otherwise keep the old theme's colour until the
  // next resize.
  observer = new MutationObserver(() => {
    readColors()
    drawBase()
    draw()
  })
  observer.observe(document.documentElement, {attributes: true, attributeFilter: ['data-theme']})
})

onUnmounted(() => {
  window.removeEventListener('resize', resize)
  window.removeEventListener('pointermove', onMove)
  document.removeEventListener('pointerleave', onLeave)
  observer?.disconnect()
  if (frame) cancelAnimationFrame(frame)
})
</script>

<template>
  <canvas v-if="fine" ref="el" class="lattice-bg" aria-hidden="true" />
</template>

<style scoped>
.lattice-bg {
  position: fixed;
  inset: 0;
  width: 100%;
  height: 100%;
  /* Behind the page's content but in front of the page background, the same
     slot the cursor glow used to occupy: it shows through the gutters between
     panels and faintly through the panels themselves. */
  z-index: -1;
  pointer-events: none;
}

/* No reduced-motion variant. The rule for every front end in this tree is that
   motion runs whatever prefers-reduced-motion says (see CLAUDE.md): Windows
   reports the preference whenever "Animation effects" is off, and on the
   machine these are built for that is not a choice anyone made. The lattice is
   static in any case; only the light under the pointer changes. */
</style>
