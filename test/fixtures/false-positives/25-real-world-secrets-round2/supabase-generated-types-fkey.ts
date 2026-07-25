// Reconstructed (anonymized/generic) from the real-world false-positive re-validation
// pass (docs/REAL_WORLD_VALIDATION.md, "Re-validation (post-fix)" section, §1 --
// react-gantt-lovable-starter). Auto-generated Supabase `database.types.ts` files emit
// foreign-key CONSTRAINT NAMES as string properties -- "foreignKeyName" matches the
// key/secret/token keyword vocabulary, and the constraint-name value is long/underscored
// enough to clear the entropy gate, even though it's a deterministic, non-secret,
// database-generated identifier, not a leaked credential.

export type Database = {
  public: {
    Tables: {
      tasks: {
        Relationships: [
          {
            foreignKeyName: "tasks_project_id_fkey";
            columns: ["project_id"];
            referencedRelation: "projects";
            referencedColumns: ["id"];
          },
          {
            foreignKeyName: "tasks_assigned_to_fkey";
            columns: ["assigned_to"];
            referencedRelation: "users";
            referencedColumns: ["id"];
          },
        ];
      };
    };
  };
};
