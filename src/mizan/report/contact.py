"""Local-only contact-channel discovery (SECURITY.md / RFC 9116 security.txt).

NO NETWORK — by design the search space is the repository files them-
selves. If nothing is found the honest answer is NO_CONTACT_FOUND; the
report never guesses a channel and the operator decides what to do.

Network enrichment (GitHub API security contact) is deliberately absent;
it would violate the local-only guarantee of every non-publish command.
"""

import re
from pathlib import Path

__all__ = ["find_contact"]

_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
_URL_RE = re.compile(r"https?://[^\s)>\]]+")

_MD_CANDIDATES = (
    "SECURITY.md", "security.md", "Security.md",
    ".github/SECURITY.md", "docs/SECURITY.md",
)
_TXT_CANDIDATES = (
    ".well-known/security.txt",   # RFC 9116 preferred location
    "security.txt",
)


def find_contact(repo: Path) -> dict:
    """Search the local repository for a disclosure contact channel."""
    repo = Path(repo)
    result = {"email": None, "url": None, "policy": None, "source": None}

    for candidate in _MD_CANDIDATES:
        path = repo / candidate
        if path.is_file():
            text = path.read_text(encoding="utf-8", errors="ignore")
            emails = _EMAIL_RE.findall(text)
            urls = _URL_RE.findall(text)
            if emails:
                result["email"] = emails[0]
            if urls:
                result["url"] = urls[0]
            result["source"] = candidate
            if not result["email"] and not result["url"]:
                # honest distinction: a policy file exists, but it names
                # no parseable channel — never guess one
                result["policy"] = "CONTACT_FILE_FOUND_NO_CHANNEL"
            return result

    for candidate in _TXT_CANDIDATES:
        path = repo / candidate
        if path.is_file():
            text = path.read_text(encoding="utf-8", errors="ignore")
            contacts = re.findall(r"(?im)^Contact:\s*(\S+)", text)
            if contacts:
                contact = contacts[0]
                if contact.startswith("http"):
                    result["url"] = contact
                else:
                    result["email"] = contact.replace("mailto:", "")
            else:
                # honest distinction, same as the SECURITY.md branch: the
                # policy file exists but names no parseable channel
                result["policy"] = "CONTACT_FILE_FOUND_NO_CHANNEL"
            result["source"] = candidate
            return result

    result["policy"] = "NO_CONTACT_FOUND"
    return result
