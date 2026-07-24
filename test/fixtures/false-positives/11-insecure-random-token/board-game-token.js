'use strict';
// FALSE POSITIVE for check 11 (insecure-random-token).
//
// Board-game UI: randomly picks which colored playing piece ("token") a new player
// gets at the table. This is a physical-game metaphor ("game token" = checkers
// piece), not a security/auth token -- nothing here grants access to anything, so
// there is no forgeability/predictability concern at all. Flagged purely because
// "gameToken" contains the substring "token".
const TOKEN_COLORS = ['red', 'blue', 'green', 'yellow'];

function assignPlayerToken() {
  const gameToken = TOKEN_COLORS[Math.floor(Math.random() * TOKEN_COLORS.length)];
  return gameToken;
}

module.exports = { assignPlayerToken };
