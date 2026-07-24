'use strict';
// FALSE POSITIVE for check 11 (insecure-random-token).
//
// Mock-data generator for testing an NLP tokenizer pipeline. "tokenizerSeed" picks
// which sample sentence gets used as a test fixture -- it contains "token" only
// because it's short for "tokenizer" (a text-processing term), and has nothing to
// do with authentication.
const SAMPLE_SENTENCES = [
  'The quick brown fox jumps over the lazy dog.',
  'Colorless green ideas sleep furiously.',
  'She sells seashells by the seashore.',
];

function pickTokenizerSeedSentence() {
  const tokenizerSeed = Math.floor(Math.random() * SAMPLE_SENTENCES.length);
  return SAMPLE_SENTENCES[tokenizerSeed];
}

module.exports = { pickTokenizerSeedSentence };
