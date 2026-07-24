'use strict';
// FALSE POSITIVE for check 11 (insecure-random-token).
//
// Debounce/dedup key for a CSS toast-animation queue -- "animationToken" is an
// internal bookkeeping id for a Map of in-flight animations, not a security token.
// Predictability here has no consequence beyond (at worst) two toasts sharing a
// queue slot.
function queueToastAnimation(queue) {
  const animationToken = Math.random().toString(36).slice(2);
  const delayMs = Math.random() * 300;
  queue.set(animationToken, { delayMs });
  return animationToken;
}

module.exports = { queueToastAnimation };
