// Positive control -- NOT a false positive. Confirms the doc-context placeholder
// suppression (Bug C) is properly SCOPED: the exact same word-shaped, underscore-separated
// value that gets suppressed inside a Markdown fenced code block (env-example-non-english.md)
// must still fire in an ordinary application source file, where there is no "this is a
// documentation example" context to justify a looser check.

const GROQ_API_KEY_FALLBACK = 'sua_chave_groq_aqui_valor_de_reserva';
