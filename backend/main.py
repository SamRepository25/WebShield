"""WebShield FastAPI backend — website security scanner."""

from __future__ import annotations

import ssl
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

app = FastAPI(
    title="WebShield API",
    description="Website security scanner — analyze headers, HTTPS, and generate a security score.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

REQUEST_TIMEOUT = 12
USER_AGENT = "WebShieldScanner/1.0 (+https://webshield.app)"

SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]

HEADER_WEIGHTS = {
    "strict-transport-security": 2.0,
    "content-security-policy": 2.5,
    "x-frame-options": 1.5,
    "x-content-type-options": 1.0,
    "referrer-policy": 1.0,
    "permissions-policy": 1.0,
}

HEADER_DESCRIPTIONS = {
    "strict-transport-security": (
        "Enforces HTTPS connections and protects against protocol downgrade attacks."
    ),
    "content-security-policy": (
        "Restricts resource loading to prevent XSS and data injection attacks."
    ),
    "x-frame-options": (
        "Prevents clickjacking by restricting the page from being embedded in iframes."
    ),
    "x-content-type-options": (
        "Prevents browsers from MIME-type sniffing and interpreting files as a different type."
    ),
    "referrer-policy": (
        "Controls how much referrer information is included with requests."
    ),
    "permissions-policy": (
        "Controls which browser features and APIs the page can access."
    ),
}

HEADER_SEVERITIES = {
    "strict-transport-security": "high",
    "content-security-policy": "high",
    "x-frame-options": "medium",
    "x-content-type-options": "medium",
    "referrer-policy": "low",
    "permissions-policy": "medium",
}


class ScanRequest(BaseModel):
    url: str = Field(..., description="Website URL to scan, with or without scheme.")


class HeaderInfo(BaseModel):
    name: str
    value: str
    status: str
    description: str
    severity: str


class HttpsInfo(BaseModel):
    enabled: bool
    valid: bool
    expiresAt: str
    issuer: str
    protocol: str
    daysRemaining: int


class Recommendation(BaseModel):
    id: str
    title: str
    description: str
    severity: str
    impact: str


class Vulnerabilities(BaseModel):
    count: int
    critical: int
    high: int
    medium: int
    low: int


class ScanResponse(BaseModel):
    url: str
    scannedAt: str
    score: int
    grade: str
    https: HttpsInfo
    headers: list[HeaderInfo]
    rawHeaders: list[dict]
    recommendations: list[Recommendation]
    vulnerabilities: Vulnerabilities


def normalize_url(raw: str) -> str:
    """Ensure the URL has a scheme; default to https."""
    url = raw.strip()
    if not url:
        raise ValueError("URL is required.")
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urlparse(url)
    if not parsed.hostname or "." not in parsed.hostname:
        raise ValueError("Please provide a valid website URL.")
    return url


def get_ssl_info(hostname: str) -> HttpsInfo:
    """Fetch SSL certificate details for the hostname."""
    default = HttpsInfo(
        enabled=False,
        valid=False,
        expiresAt="",
        issuer="",
        protocol="",
        daysRemaining=0,
    )
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=REQUEST_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version() or ""
    except (socket.timeout, socket.gaierror, ssl.SSLError, OSError, ConnectionRefusedError):
        return default

    if not cert:
        return default

    not_after = cert.get("notAfter", "")
    try:
        expiry_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        expiry_dt = expiry_dt.replace(tzinfo=timezone.utc)
    except ValueError:
        expiry_dt = datetime.now(timezone.utc)

    issuer_parts = cert.get("issuer", ())
    issuer_name = ""
    for rdn in issuer_parts:
        for attr in rdn:
            key, value = attr
            if key in ("organizationName", "commonName"):
                issuer_name = value
                break
        if issuer_name:
            break

    days_remaining = (expiry_dt - datetime.now(timezone.utc)).days

    return HttpsInfo(
        enabled=True,
        valid=True,
        expiresAt=expiry_dt.strftime("%Y-%m-%d") if not_after else "",
        issuer=issuer_name or "Unknown CA",
        protocol=protocol,
        daysRemaining=max(days_remaining, 0),
    )


def analyze_headers(headers: dict) -> tuple[list[HeaderInfo], int, Vulnerabilities]:
    """Analyze security headers and compute score + vulnerability counts."""
    lower_headers = {k.lower(): v for k, v in headers.items()}
    header_infos: list[HeaderInfo] = []
    total_weight = sum(HEADER_WEIGHTS.values())
    earned_weight = 0.0

    vuln_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    for header_name in SECURITY_HEADERS:
        value = lower_headers.get(header_name, "")
        present = bool(value)

        if present:
            status = "present"
            earned_weight += HEADER_WEIGHTS[header_name]
        else:
            status = "missing"
            severity = HEADER_SEVERITIES[header_name]
            if severity in vuln_counts:
                vuln_counts[severity] += 1

        header_infos.append(
            HeaderInfo(
                name=_pretty_header_name(header_name),
                value=value if value else "Not set",
                status=status,
                description=HEADER_DESCRIPTIONS[header_name],
                severity=HEADER_SEVERITIES[header_name],
            )
        )

    score = round((earned_weight / total_weight) * 100) if total_weight else 0
    vulnerabilities = Vulnerabilities(
        count=sum(vuln_counts.values()),
        **vuln_counts,
    )
    return header_infos, score, vulnerabilities


def _pretty_header_name(name: str) -> str:
    """Convert header key to standard Title-Case form."""
    special = {
        "strict-transport-security": "Strict-Transport-Security",
        "content-security-policy": "Content-Security-Policy",
        "x-frame-options": "X-Frame-Options",
        "x-content-type-options": "X-Content-Type-Options",
        "referrer-policy": "Referrer-Policy",
        "permissions-policy": "Permissions-Policy",
    }
    return special.get(name, name.title())


def grade_from_score(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    if score >= 50:
        return "E"
    return "F"


def build_recommendations(header_infos: list[HeaderInfo], https_info: HttpsInfo) -> list[Recommendation]:
    """Generate actionable recommendations based on findings."""
    recs: list[Recommendation] = []
    missing = {h.name.lower(): h for h in header_infos if h.status == "missing"}

    rec_map = {
        "strict-transport-security": {
            "title": "Add Strict-Transport-Security (HSTS) header",
            "description": "HSTS is missing. Add it to force browsers to always use HTTPS and prevent protocol downgrade attacks.",
            "impact": "Protects against man-in-the-middle and SSL stripping attacks.",
        },
        "content-security-policy": {
            "title": "Add Content-Security-Policy header",
            "description": "CSP is missing. Without it, your site is more vulnerable to XSS and data injection attacks.",
            "impact": "Significantly reduces risk of Cross-Site Scripting (XSS) attacks.",
        },
        "x-frame-options": {
            "title": "Add X-Frame-Options header",
            "description": "X-Frame-Options is missing. Add it to prevent clickjacking by stopping your page from being embedded in iframes.",
            "impact": "Prevents clickjacking attacks on your users.",
        },
        "x-content-type-options": {
            "title": "Add X-Content-Type-Options header",
            "description": "X-Content-Type-Options is missing. Set it to 'nosniff' to prevent browsers from MIME-type sniffing.",
            "impact": "Reduces risk of content type confusion attacks.",
        },
        "referrer-policy": {
            "title": "Add Referrer-Policy header",
            "description": "Referrer-Policy is missing. Add it to control how much referrer information is shared with external sites.",
            "impact": "Protects user privacy by limiting referrer data leakage.",
        },
        "permissions-policy": {
            "title": "Add Permissions-Policy header",
            "description": "Permissions-Policy is missing. Add it to restrict access to browser features like camera, microphone, and geolocation.",
            "impact": "Limits attack surface by restricting powerful browser APIs.",
        },
    }

    for idx, (key, info) in enumerate(missing.items(), start=1):
        template = rec_map.get(key)
        if not template:
            continue
        recs.append(
            Recommendation(
                id=f"rec-{idx}",
                title=template["title"],
                description=template["description"],
                severity=info.severity,
                impact=template["impact"],
            )
        )

    if https_info.enabled and https_info.daysRemaining < 30:
        recs.append(
            Recommendation(
                id=f"rec-{len(recs) + 1}",
                title="Renew SSL certificate soon",
                description=(
                    f"Your SSL certificate expires in {https_info.daysRemaining} days. "
                    "Renew it before it lapses to avoid browser warnings."
                ),
                severity="high",
                impact="Prevents HTTPS warnings and loss of trust from visitors.",
            )
        )

    if not https_info.enabled:
        recs.append(
            Recommendation(
                id=f"rec-{len(recs) + 1}",
                title="Enable HTTPS",
                description="Your site does not serve over HTTPS. Obtain an SSL certificate and redirect all HTTP traffic to HTTPS.",
                severity="critical",
                impact="HTTPS is foundational for web security and user trust.",
            )
        )

    return recs


@app.get("/")
def health() -> dict:
    return {"status": "ok", "service": "WebShield API", "version": "1.0.0"}


@app.post("/api/scan", response_model=ScanResponse)
def scan(request: ScanRequest) -> ScanResponse:
    try:
        url = normalize_url(request.url)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    try:
        response = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": USER_AGENT},
            allow_redirects=True,
            verify=True,
        )
    except requests.exceptions.SSLError as exc:
        raise HTTPException(
            status_code=422,
            detail=f"SSL verification failed for {hostname}: {exc}",
        ) from exc
    except requests.exceptions.ConnectionError as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Could not connect to {hostname}. The site may be offline or unreachable.",
        ) from exc
    except requests.exceptions.Timeout as exc:
        raise HTTPException(
            status_code=504,
            detail=f"Request to {hostname} timed out.",
        ) from exc
    except requests.exceptions.RequestException as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Failed to fetch {hostname}: {exc}",
        ) from exc

    headers_dict = dict(response.headers)
    https_info = get_ssl_info(hostname)
    header_infos, score, vulnerabilities = analyze_headers(headers_dict)
    recommendations = build_recommendations(header_infos, https_info)

    raw_headers = [{"name": k, "value": v} for k, v in headers_dict.items()]

    return ScanResponse(
        url=url,
        scannedAt=datetime.now(timezone.utc).isoformat(),
        score=score,
        grade=grade_from_score(score),
        https=https_info,
        headers=header_infos,
        rawHeaders=raw_headers,
        recommendations=recommendations,
        vulnerabilities=vulnerabilities,
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
