These are TEMPLATE/example env files with only placeholder content. None should be
reported by check 2 (secret-env-committed) -- they are the moral equivalent of
.env.example. But check 2 flags all of them (false positives) because
SAFE_ENV_TEMPLATE_NAMES only lists the four dot-separated names
(.env.example/.sample/.template/.dist) while ENV_FILE_RE was later broadened to accept
-/_ separators and arbitrary compound suffixes.
