// EVASION (round 3): check 6 (cors-wildcard-with-credentials) where the wildcard origin
// variable has a TypeScript TYPE ANNOTATION. CORS_ORIGIN_VAR_RE captures `allowedOrigin`,
// but findVarAssignmentContainingWildcard's declaration regex
//   /(?:const|let|var)\s+NAME\s*=\s*([^;\n]+)/
// requires the name to be followed directly by `=`. The `: string` annotation between the
// name and `=` defeats resolution, so the '*' is never seen.
import express from 'express';
import cors from 'cors';

const app = express();

const allowedOrigin: string = '*';

app.use(
  cors({
    origin: allowedOrigin,
    credentials: true,
  }),
);

export default app;
