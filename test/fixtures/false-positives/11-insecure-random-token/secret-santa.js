'use strict';
// FALSE POSITIVE for check 11 (insecure-random-token).
//
// Recipe randomizer for a cooking-tips app -- picks a random "secret ingredient" to
// suggest to the user. "secretIngredient" here is a cooking metaphor, not a
// security secret: nothing here is confidential or grants access to anything, so
// Math.random()'s predictability has zero security consequence. The check flags
// this purely because the variable name contains the substring "secret", which is
// part of its keyword vocabulary for security-sensitive token names.
function suggestSecretIngredient() {
  const secretIngredient = Math.random() < 0.5 ? 'ketchup' : 'mustard';
  return secretIngredient;
}

module.exports = { suggestSecretIngredient };
