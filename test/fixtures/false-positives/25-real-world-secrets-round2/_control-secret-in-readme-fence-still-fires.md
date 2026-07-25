# Sample Project

Positive control -- NOT a false positive. A REAL-looking secret pasted into a README code
fence (a common real mistake -- someone pastes a live key into setup docs) must still be
flagged; the doc-context placeholder suppression is scoped to word-shaped (pure-lowercase,
underscore/hyphen-separated) values, not to every value that happens to sit inside a fence.

```
GROQ_API_KEY=zK9mQ2xL7pR4vN8jT1cB6wY3hD0sU5gA
```
