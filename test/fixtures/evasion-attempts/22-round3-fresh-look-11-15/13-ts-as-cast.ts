// Check 13 candidate: TypeScript `as` cast on req.body passed straight into a write call.
// `req.body as CreateUserDto` is not the exact text `req.body`, not a bare identifier, and
// not a `{ ... }` literal -- so argIsWholeReqBodyOrQuery matches none of its branches.
// This is idiomatic TS, not obfuscation.

interface CreateUserDto {
  email: string;
  name: string;
}

export async function createUser(req: any, res: any) {
  const user = await User.create(req.body as CreateUserDto);
  res.json(user);
}

declare const User: any;
