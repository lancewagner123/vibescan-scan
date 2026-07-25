// Check 13 candidate: TypeScript non-null assertion on req.body. `req.body!` is the same
// whole, unfiltered object, but the trailing `!` means it is not the exact text `req.body`
// and not a bare identifier, so argIsWholeReqBodyOrQuery rejects it.

export async function updateProfile(req: any, res: any) {
  const updated = await User.findByIdAndUpdate(req.params.id, req.body!);
  res.json(updated);
}

declare const User: any;
