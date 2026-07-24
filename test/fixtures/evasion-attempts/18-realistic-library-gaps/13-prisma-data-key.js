'use strict';
// NEW gap for check 13 (mass-assignment), found by a realistic-library-code audit
// (round 2, 2026-07-24) -- not an adversarial evasion trick, just Prisma's standard call
// shape. Prisma's ENTIRE write API nests the actual payload one level down under a
// `data:` key (`prisma.user.create({ data: req.body })`), instead of passing req.body as
// the top-level argument the way Mongoose/Sequelize do. argIsWholeReqBodyOrQuery() only
// recognized a bare req.body/req.query, a `{...req.body}` spread, or a resolvable
// identifier -- never an object literal wrapping req.body one level down under a named
// key -- so despite Prisma being one of the three ORMs this check's own doc comment names
// as a target, this shape was completely unreachable before.
async function updateUser(prisma, req, res) {
  const user = await prisma.user.create({ data: req.body });
  res.json(user);
}

module.exports = { updateUser };
