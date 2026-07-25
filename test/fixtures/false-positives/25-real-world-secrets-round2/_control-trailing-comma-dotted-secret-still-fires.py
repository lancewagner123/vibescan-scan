# Positive control -- NOT a false positive. Confirms the trailing-comma stripping added to
# looksLikeCodeReference (needed so a Python kwarg's trailing comma doesn't block
# recognition of a genuine self.X reference, since GENERIC_ENTROPY_UNQUOTED_RE's value
# character class does not exclude a comma) does not ALSO cause a real, dotted, high-entropy
# secret written in the same "NAME=value," kwarg-line shape to be wrongly suppressed.

def build_client(self):
    return SomeSdk(
        api_secret_key=mR7xK2pL9vQ4.tY8wZ1aB6cD3eF5gH0iJ,
    )
