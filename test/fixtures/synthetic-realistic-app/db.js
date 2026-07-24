'use strict';

// Minimal fake pg-like client so the rest of this fixture's query-shape code looks like
// real Postgres access without actually needing a database connection. Every route file
// in this fixture requires this instead of 'pg' directly.
const pool = {
  query(sql, params) {
    return Promise.resolve({ rows: [], sql, params });
  },
};

module.exports = pool;
