"""WebShield FastAPI backend — website security scanner."""

from __future__ import annotations

import ipaddress
import os
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import requests
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from rate_limit import check_rate_limit

app = FastAPI(
    title="WebShield API",
    description="Website security scanner — analyze headers, HTTPS, and generate a security score.",
    version="1.1.0",
)

frontend_origin = os.getenv("FRONTEND_ORIGIN", "https://webshield-zpv1.onrender.com").rstrip("/")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[frontend_origin],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-WebShield-Secret"],
)

REQUEST_TIMEOUT = 12
MAX_REDIRECTS = 10
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
    "strict-transport-security": "Enforces HTTPS connections and protects against protocol downgrade attacks.",
    "content-security-policy": "Restricts resource loading to prevent XSS and data injection attacks.",
    "x-frame-options": "Prevents clickjacking by restricting the page from being embedded in iframes.",
    "x-content-type-options": "Prevents browsers from MIME-type sniffing and interpreting files as a different type.",
    "referrer-policy": "Controls how much referrer information is included with requests.",
    "permissions-policy": "Controls which browser features and APIs the page can access.",
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
    url = raw.strip()
    if not url:
        raise ValueError("URL is required.")
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Please provide a valid public website URL.")
    if parsed.port not in (None, 80, 443):
        raise ValueError("Only standard HTTP and HTTPS ports are allowed.")
    return url


def assert_public_target(url: str) -> str:
    parsed = urlparse(normalize_url(url))
    hostname = parsed.hostname or ""
    lowered = hostname.lower().rstrip(".")
    blocked_names = {"localhost", "metadata.google.internal", "metadata", "host.docker.internal"}
    if lowered in blocked_names or lowered.endswith((".localhost", ".local", ".internal")):
        raise ValueError("Private or internal network targets are not allowed.")

    try:
        addresses = {info[4][0] for info in socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)}
    except socket.gaierror as exc:
        raise ValueError("Could not resolve the target hostname.") from exc

    if not addresses or any(not ipaddress.ip_address(address).is_global for address in addresses):
        raise ValueError("The target resolves to a private or reserved network address.")
    return parsed.geturl()


def get_ssl_info(hostname: str) -> HttpsInfo:
    default = HttpsInfo(enabled=False, valid=False, expiresAt="", issuer="", protocol="", daysRemaining=0)
    try:
        assert_public_target(f"https://{hostname}")
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=REQUEST_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version() or ""
    except (ValueError, socket.timeout, socket.gaierror, ssl.SSLError, OSError, ConnectionRefusedError):
        return default

    if not cert:
        return default

    not_after = cert.get("notAfter", "")
    try:
        expiry_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
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
    vulnerabilities = Vulnerabilities(count=sum(vuln_counts.values()), **vuln_counts)
    return header_infos, score, vulnerabilities


def _pretty_header_name(name: str) -> str:
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
    recs: list[Recommendation] = []
    missing = {h.name.lower(): h for h in header_infos if h.status == "missing"}
    rec_map = {
        "strict-transport-security": ("Add Strict-Transport-Security (HSTS) header", "HSTS is missing. Add it to force browsers to always use HTTPS and prevent protocol downgrade attacks.", "Protects against man-in-the-middle and SSL stripping attacks."),
        "content-security-policy": ("Add Content-Security-Policy header", "CSP is missing. Without it, your site is more vulnerable to XSS and data injection attacks.", "Significantly reduces risk of Cross-Site Scripting (XSS) attacks."),
        "x-frame-options": ("Add X-Frame-Options header", "X-Frame-Options is missing. Add it to prevent clickjacking by stopping your page from being embedded in iframes.", "Prevents clickjacking attacks on your users."),
        "x-content-type-options": ("Add X-Content-Type-Options header", "X-Content-Type-Options is missing. Set it to 'nosniff' to prevent browsers from MIME-type sniffing.", "Reduces risk of content type confusion attacks."),
        "referrer-policy": ("Add Referrer-Policy header", "Referrer-Policy is missing. Add it to control how much referrer information is shared with external sites.", "Protects user privacy by limiting referrer data leakage."),
        "permissions-policy": ("Add Permissions-Policy header", "Permissions-Policy is missing. Add it to restrict access to browser features like camera, microphone, and geolocation.", "Limits attack surface by restricting powerful browser APIs."),
    }

    for idx, (key, info) in enumerate(missing.items(), start=1):
        template = rec_map.get(key)
        if not template:
            continue
        recs.append(Recommendation(id=f"rec-{idx}", title=template[0], description=template[1], severity=info.severity, impact=template[2]))

    if https_info.enabled and https_info.daysRemaining < 30:
        recs.append(Recommendation(id=f"rec-{len(recs) + 1}", title="Renew SSL certificate soon", description=f"Your SSL certificate expires in {https_info.daysRemaining} days. Renew it before it lapses to avoid browser warnings.", severity="high", impact="Prevents HTTPS warnings and loss of trust from visitors."))

    if not https_info.enabled:
        recs.append(Recommendation(id=f"rec-{len(recs) + 1}", title="Enable HTTPS", description="Your site does not serve over HTTPS. Obtain an SSL certificate and redirect all HTTP traffic to HTTPS.", severity="critical", impact="HTTPS is foundational for web security and user trust."))

    return recs


@app.get("/")
def health() -> dict:
    return {"status": "ok", "service": "WebShield API", "version": "1.1.0"}


@app.post("/api/scan", response_model=ScanResponse)
def scan(request: Request, payload: ScanRequest) -> ScanResponse:
    forwarded = request.headers.get("x-forwarded-for", "")
    identifier = forwarded.split(",")[0].strip() or (request.client.host if request.client else "unknown")
    try:
        allowed, retry_after = check_rate_limit(identifier)
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Rate limiter unavailable. Please try again later.") from exc
    if not allowed:
        raise HTTPException(status_code=429, detail=f"Too many scan requests. Please try again in {retry_after} seconds.", headers={"Retry-After": str(retry_after)})

    try:
        current_url = assert_public_target(payload.url)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    redirect_count = 0
    visited: set[str] = set()
    response: requests.Response | None = None

    try:
        while True:
            current_url = assert_public_target(current_url)
            if current_url in visited:
                raise HTTPException(status_code=508, detail="Redirect loop detected.")
            visited.add(current_url)

            response = requests.get(
                current_url,
                timeout=REQUEST_TIMEOUT,
                headers={"User-Agent": USER_AGENT},
                allow_redirects=False,
                verify=True,
            )

            if response.is_redirect or response.is_permanent_redirect:
                location = response.headers.get("Location")
                if not location:
                    break
                redirect_count += 1
                if redirect_count > MAX_REDIRECTS:
                    raise HTTPException(status_code=508, detail="Too many redirects.")
                current_url = urljoin(current_url, location)
                continue
            break
    except HTTPException:
        raise
    except requests.exceptions.SSLError as exc:
        raise HTTPException(status_code=422, detail=f"SSL verification failed: {exc}") from exc
    except requests.exceptions.ConnectionError as exc:
        raise HTTPException(status_code=502, detail="Could not connect to the target site.") from exc
    except requests.exceptions.Timeout as exc:
        raise HTTPException(status_code=504, detail="The target site timed out.") from exc
    except requests.exceptions.RequestException as exc:
        raise HTTPException(status_code=502, detail=f"Failed to fetch the target site: {exc}") from exc

    if response is None:
        raise HTTPException(status_code=502, detail="No response received from the target site.")

    parsed = urlparse(current_url)
    hostname = parsed.hostname or ""
    headers_dict = dict(response.headers)
    https_info = get_ssl_info(hostname) if parsed.scheme == "https" else HttpsInfo(enabled=False, valid=False, expiresAt="", issuer="", protocol="", daysRemaining=0)
    header_infos, score, vulnerabilities = analyze_headers(headers_dict)
    recommendations = build_recommendations(header_infos, https_info)
    raw_headers = [{"name": k, "value": v} for k, v in headers_dict.items()]

    return ScanResponse(
        url=current_url,
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
