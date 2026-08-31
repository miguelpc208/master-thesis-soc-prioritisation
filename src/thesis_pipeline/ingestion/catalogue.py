from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable

CVE_ID_PATTERN = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")


def canonical_cve_ids_sha256(cve_ids: Iterable[str]) -> str:
    """Hash the exact sorted canonical CVE identity set, not only its cardinality."""
    identifiers = sorted({str(value).upper() for value in cve_ids})
    if not identifiers or any(CVE_ID_PATTERN.fullmatch(value) is None for value in identifiers):
        raise ValueError("The canonical CVE catalogue contains invalid identifiers")
    material = "".join(f"{identifier}\n" for identifier in identifiers)
    return hashlib.sha256(material.encode("ascii")).hexdigest()
