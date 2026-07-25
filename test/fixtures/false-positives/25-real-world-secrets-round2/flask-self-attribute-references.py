# Reconstructed (anonymized/generic) from the real-world false-positive re-validation pass
# (docs/REAL_WORLD_VALIDATION.md, "Re-validation (post-fix)" section, §1 -- Vibelens, a
# Python/Flask backend). `self.access_key`/`self.secret_key` are dotted ATTRIBUTE
# REFERENCES (an object reading its own instance attribute) passed as keyword arguments --
# the same conceptual shape as `process.env.X`, a reference rather than a literal value --
# but the original fix's four-hardcoded-root allowlist (process.env./import.meta.env./
# Deno.env./Bun.env.) didn't recognize Python's `self.` idiom at all.

class StorageClient:
    def __init__(self, access_key, secret_key):
        self.access_key = access_key
        self.secret_key = secret_key

    def build_client(self):
        return boto3.client(
            "s3",
            aws_access_key_id=self.access_key,
            aws_secret_access_key=self.secret_key,
        )
