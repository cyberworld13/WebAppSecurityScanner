import time
import requests

from urllib.parse import urlparse, urljoin, urldefrag
from bs4 import BeautifulSoup
from scanner.vulnerabilities import (
    analyze_forms,
    get_url_parameters,
    test_reflected_input
)
SECURITY_HEADERS = {
    "Content-Security-Policy": "Helps prevent XSS and content injection attacks.",
    "Strict-Transport-Security": "Forces browsers to use HTTPS.",
    "X-Content-Type-Options": "Helps prevent MIME-type sniffing.",
    "X-Frame-Options": "Helps prevent clickjacking.",
    "Referrer-Policy": "Controls how much referrer information is shared.",
    "Permissions-Policy": "Controls access to browser features."
}

def analyze_security_header_values(headers):
    """
    Check selected security-header values for common
    configuration problems. These checks are indicators,
    not a complete validation of browser security.
    """

    warnings = []

    # 1. Content Security Policy
    csp = headers.get("Content-Security-Policy", "")

    if csp:
        csp_lower = csp.lower()

        if "'unsafe-eval'" in csp_lower:
            warnings.append({
                "header": "Content-Security-Policy",
                "severity": "Medium",
                "issue": "CSP permits unsafe-eval",
                "evidence": csp,
                "recommendation": (
                    "Avoid 'unsafe-eval' where possible and "
                    "review whether the application requires it."
                )
            })

        if "'unsafe-inline'" in csp_lower:
            warnings.append({
                "header": "Content-Security-Policy",
                "severity": "Medium",
                "issue": "CSP permits unsafe-inline",
                "evidence": csp,
                "recommendation": (
                    "Prefer nonces or hashes for scripts and "
                    "styles where supported."
                )
            })

        if "default-src" not in csp_lower:
            warnings.append({
                "header": "Content-Security-Policy",
                "severity": "Low",
                "issue": "CSP has no default-src directive",
                "evidence": csp,
                "recommendation": (
                    "Review whether a restrictive default-src "
                    "directive is appropriate for the application."
                )
            })

    # 2. Strict Transport Security
    hsts = headers.get("Strict-Transport-Security", "")

    if hsts:
        hsts_lower = hsts.lower()

        if "max-age" not in hsts_lower:
            warnings.append({
                "header": "Strict-Transport-Security",
                "severity": "Medium",
                "issue": "HSTS has no max-age directive",
                "evidence": hsts,
                "recommendation": (
                    "Configure an appropriate max-age after "
                    "reviewing HTTPS deployment requirements."
                )
            })
        else:
            import re

            match = re.search(
                r"(?:^|;)\s*max-age\s*=\s*(\d+)",
                hsts_lower
            )

            if match and int(match.group(1)) == 0:
                warnings.append({
                    "header": "Strict-Transport-Security",
                    "severity": "Medium",
                    "issue": "HSTS max-age is zero",
                    "evidence": hsts,
                    "recommendation": (
                        "Review the HSTS policy; max-age=0 "
                        "instructs browsers to clear the policy."
                    )
                })

    # 3. X-Content-Type-Options
    xcto = headers.get("X-Content-Type-Options", "")

    if xcto and xcto.strip().lower() != "nosniff":
        warnings.append({
            "header": "X-Content-Type-Options",
            "severity": "Low",
            "issue": "Unexpected X-Content-Type-Options value",
            "evidence": xcto,
            "recommendation": (
                "Use the standard nosniff value where "
                "appropriate."
            )
        })

    # 4. X-Frame-Options
    xfo = headers.get("X-Frame-Options", "")

    if xfo and xfo.strip().upper() not in ("DENY", "SAMEORIGIN"):
        warnings.append({
            "header": "X-Frame-Options",
            "severity": "Low",
            "issue": "Unrecognized X-Frame-Options value",
            "evidence": xfo,
            "recommendation": (
                "Review the framing policy. CSP frame-ancestors "
                "is the more flexible modern control."
            )
        })

    # 5. Referrer-Policy
    referrer = headers.get("Referrer-Policy", "")

    if referrer:
        valid_policies = {
            "no-referrer",
            "no-referrer-when-downgrade",
            "origin",
            "origin-when-cross-origin",
            "same-origin",
            "strict-origin",
            "strict-origin-when-cross-origin",
            "unsafe-url"
        }

        policies = [
            item.strip().lower()
            for item in referrer.split(",")
        ]

        final_policy = policies[-1] if policies else ""

        if final_policy not in valid_policies:
            warnings.append({
                "header": "Referrer-Policy",
                "severity": "Low",
                "issue": "Unrecognized Referrer-Policy value",
                "evidence": referrer,
                "recommendation": (
                    "Choose a documented Referrer-Policy "
                    "that fits the application's privacy needs."
                )
            })

        elif final_policy == "unsafe-url":
            warnings.append({
                "header": "Referrer-Policy",
                "severity": "Medium",
                "issue": "Referrer policy may expose URL details",
                "evidence": referrer,
                "recommendation": (
                    "Consider strict-origin-when-cross-origin "
                    "or a more restrictive policy."
                )
            })

    return warnings


def create_finding(
    title,
    severity,
    description,
    evidence,
    impact,
    recommendation,
    owasp
):
    """
    Create a standardized security finding.
    """

    return {
        "title": title,
        "severity": severity,
        "description": description,
        "evidence": evidence,
        "impact": impact,
        "recommendation": recommendation,
        "owasp": owasp
    }


def validate_url(url):
    """
    Check whether the supplied URL uses HTTP or HTTPS
    and contains a valid hostname.
    """

    parsed = urlparse(url)

    if parsed.scheme not in ["http", "https"]:
        return False

    if not parsed.netloc:
        return False

    return True


def get_domain(url):
    """
    Return the hostname of a URL.
    """

    return urlparse(url).netloc.lower()


def is_same_domain(base_url, target_url):
    """
    Allow crawling only inside the original target domain.
    """

    return get_domain(base_url) == get_domain(target_url)


def normalize_url(base_url, link):
    """
    Convert a discovered link into an absolute URL.
    """

    absolute_url = urljoin(base_url, link)

    absolute_url, _ = urldefrag(absolute_url)

    return absolute_url


def extract_links(page_url, html, base_domain):
    """
    Extract same-domain links from an HTML page.
    """

    soup = BeautifulSoup(html, "html.parser")

    links = []

    for anchor in soup.find_all("a", href=True):

        href = anchor.get("href").strip()

        if not href:
            continue

        if href.startswith(("#", "mailto:", "javascript:", "tel:")):
            continue

        full_url = normalize_url(page_url, href)

        if is_same_domain(base_domain, full_url):

            if full_url not in links:
                links.append(full_url)

    return links


def extract_forms(page_url, html):
    """
    Extract forms and their input fields from an HTML page.
    """

    soup = BeautifulSoup(html, "html.parser")

    forms = []

    for form in soup.find_all("form"):

        action = form.get("action", "")

        method = form.get("method", "GET").upper()

        form_action = normalize_url(page_url, action)

        inputs = []

        for field in form.find_all(
            ["input", "textarea", "select"]
        ):

            field_name = field.get("name")

            field_type = field.get("type", "text")

            if field_name:

                inputs.append({
                    "name": field_name,
                    "type": field_type
                })

        forms.append({
            "action": form_action,
            "method": method,
            "inputs": inputs
        })

    return forms


def detect_technology(response, html):
    """
    Detect basic technology clues from headers and HTML.
    """

    technologies = []

    server = response.headers.get("Server", "")

    powered_by = response.headers.get(
        "X-Powered-By",
        ""
    )

    html_lower = html.lower()

    if server:

        technologies.append(
            f"Server: {server}"
        )

    if powered_by:

        technologies.append(
            f"X-Powered-By: {powered_by}"
        )

    if "wp-content" in html_lower:

        technologies.append("WordPress")

    if "wp-includes" in html_lower:

        technologies.append("WordPress")

    if "jquery" in html_lower:

        technologies.append("jQuery")

    if "bootstrap" in html_lower:

        technologies.append("Bootstrap")

    return list(dict.fromkeys(technologies))


def crawl_target(session, target_url, max_pages=10):
    """
    Crawl a limited number of pages on the same domain.
    """

    base_domain = target_url

    queue = [target_url]

    visited = set()

    pages = []

    while queue and len(visited) < max_pages:

        current_url = queue.pop(0)

        if current_url in visited:
            continue

        if not is_same_domain(
            base_domain,
            current_url
        ):
            continue

        visited.add(current_url)

        try:

            response = session.get(
                current_url,
                timeout=10,
                allow_redirects=True
            )

            content_type = response.headers.get(
                "Content-Type",
                ""
            ).lower()

            page_info = {
                "url": current_url,
                "status_code": response.status_code,
                "content_type": content_type,
                "links": [],
                "forms": [],
                "technologies": []
            }

            if "text/html" not in content_type:

                pages.append(page_info)

                continue

            html = response.text

            discovered_links = extract_links(
                current_url,
                html,
                base_domain
            )

            forms = extract_forms(
                current_url,
                html
            )

            technologies = detect_technology(
                response,
                html
            )

            page_info["links"] = discovered_links

            page_info["forms"] = forms

            page_info["technologies"] = technologies

            pages.append(page_info)

            for link in discovered_links:

                if (
                    link not in visited
                    and link not in queue
                ):

                    if (
                        len(visited) + len(queue)
                        < max_pages
                    ):

                        queue.append(link)

        except requests.RequestException:

            continue

    return pages


def run_passive_checks(response, html):
    """
    Perform passive security checks on the HTTP response
    and page content.
    """

    findings = []

    # Preserve security-header configuration warnings.
    header_warnings = analyze_security_header_values(
        response.headers
    )

    for warning in header_warnings:
        findings.append(
            create_finding(
                title=(
                    f"Security Header Misconfiguration: "
                    f"{warning['issue']}"
                ),
                severity=warning["severity"],
                description=(
                    f"The {warning['header']} response header "
                    f"may have a configuration issue."
                ),
                evidence=warning["evidence"],
                impact=(
                    "An unsuitable security-header configuration "
                    "may weaken browser-side protections."
                ),
                recommendation=warning["recommendation"],
                owasp="A02: Security Misconfiguration"            
            )
        )

    # -----------------------------------------
    # 1. Server Information Disclosure
    # -----------------------------------------

    server = response.headers.get("Server")

    if server:

        findings.append(
            create_finding(
                title="Server Information Disclosure",
                severity="Low",
                description=(
                    "The web server identifies itself "
                    "through the Server response header."
                ),
                evidence=(
                    f"Server: {server}"
                ),
                impact=(
                    "Detailed server information can help "
                    "attackers identify the technology "
                    "and potentially target known weaknesses."
                ),
                recommendation=(
                    "Minimize unnecessary server information "
                    "exposed through HTTP response headers."
                ),
                owasp="A02: Security Misconfiguration"
            )
        )

    # -----------------------------------------
    # 2. X-Powered-By Information Disclosure
    # -----------------------------------------

    powered_by = response.headers.get(
        "X-Powered-By"
    )

    if powered_by:

        findings.append(
            create_finding(
                title="Technology Information Disclosure",
                severity="Low",
                description=(
                    "The application exposes technology "
                    "information through the X-Powered-By header."
                ),
                evidence=(
                    f"X-Powered-By: {powered_by}"
                ),
                impact=(
                    "Technology details may help attackers "
                    "identify the application stack and "
                    "research relevant vulnerabilities."
                ),
                recommendation=(
                    "Remove or minimize unnecessary "
                    "technology-identifying response headers."
                ),
                owasp="A02: Security Misconfiguration"
            )
        )

    # -----------------------------------------
    # 3. Dangerous HTTP Methods
    # -----------------------------------------

    allow_header = response.headers.get("Allow", "")

    if allow_header:

        methods = [
            method.strip().upper()
            for method in allow_header.split(",")
        ]

        dangerous_methods = [
            method
            for method in methods
            if method in ["PUT", "DELETE", "TRACE"]
        ]

        if dangerous_methods:

            findings.append(
                create_finding(
                    title="Potentially Risky HTTP Methods Enabled",
                    severity="Medium",
                    description=(
                        "The server advertises HTTP methods "
                        "that may require additional security controls."
                    ),
                    evidence=(
                        f"Allow header: {allow_header}"
                    ),
                    impact=(
                        "Improperly configured HTTP methods "
                        "may allow unintended modification, "
                        "deletion, or diagnostic behavior."
                    ),
                    recommendation=(
                        "Disable HTTP methods that are not "
                        "required by the application."
                    ),
                    owasp="A02: Security Misconfiguration"
                )
            )

    # -----------------------------------------
    # 4. Directory Listing Indicator
    # -----------------------------------------

    soup = BeautifulSoup(
        html,
        "html.parser"
    )

    page_title = soup.title

    if page_title:

        title_text = page_title.get_text(
            strip=True
        ).lower()

        if (
            "index of /" in title_text
            or "directory listing" in title_text
        ):

            findings.append(
                create_finding(
                    title="Possible Directory Listing",
                    severity="Medium",
                    description=(
                        "The page appears to expose a "
                        "directory listing."
                    ),
                    evidence=(
                        f"Page title: {page_title.get_text(strip=True)}"
                    ),
                    impact=(
                        "Directory listings can expose "
                        "files and application resources "
                        "that were not intended to be public."
                    ),
                    recommendation=(
                        "Disable directory indexing unless "
                        "it is explicitly required."
                    ),
                    owasp="A02: Security Misconfiguration"
                )
            )

    # -----------------------------------------
    # 5. Sensitive Information Exposure
    # -----------------------------------------

    sensitive_patterns = [
        "password",
        "api_key",
        "apikey",
        "secret_key",
        "access_token",
        "private_key"
    ]

    html_lower = html.lower()

    detected_patterns = []

    for pattern in sensitive_patterns:

        if pattern in html_lower:

            detected_patterns.append(pattern)

    if detected_patterns:

        findings.append(
            create_finding(
                title="Possible Sensitive Information Exposure",
                severity="Medium",
                description=(
                    "Potentially sensitive keywords were "
                    "detected in the HTML response."
                ),
                evidence=(
                    "Detected keywords: "
                    + ", ".join(detected_patterns)
                ),
                impact=(
                    "Sensitive information accidentally exposed "
                    "in client-accessible content may be misused."
                ),
                recommendation=(
                    "Review the detected content and ensure "
                    "secrets, credentials, and private data "
                    "are not exposed to clients."
                ),
                owasp="Needs Manual Review"            
            )
        )

    return findings



def scan_target(url):
    """
    Main passive scanning function.
    """

    result = {
        "target": url,
        "status_code": None,
        "response_time": None,
        "final_url": None,
        "https": False,
        "server": "Not disclosed",
        "content_type": "Unknown",

        "security_headers": [],
        "missing_headers": [],

        "cookies": [],
        "findings": [],

        "pages": [],
        "forms": [],
        "technologies": [],
        "interesting_inputs": [],
        "parameters": [],
        "reflection_tests": [],
        "total_pages": 0,
        "total_links": 0,
        "total_forms": 0,

        "error": None
    }

    # -----------------------------------------
    # 1. Validate URL
    # -----------------------------------------

    if not validate_url(url):

        result["error"] = (
            "Invalid URL. Please enter a valid "
            "HTTP or HTTPS URL."
        )

        return result

    # -----------------------------------------
    # 2. Create HTTP session
    # -----------------------------------------

    session = requests.Session()

    session.headers.update({
        "User-Agent": "WebApplicationSecurityScanner/1.0"
    })

    # -----------------------------------------
    # 3. Initial request
    # -----------------------------------------

    try:

        start_time = time.perf_counter()

        response = session.get(
            url,
            timeout=10,
            allow_redirects=True
        )

        end_time = time.perf_counter()

        result["status_code"] = response.status_code

        result["response_time"] = round(
            end_time - start_time,
            3
        )

        result["final_url"] = response.url

        result["https"] = response.url.lower().startswith(
            "https://"
        )

        result["server"] = response.headers.get(
            "Server",
            "Not disclosed"
        )

        result["content_type"] = response.headers.get(
            "Content-Type",
            "Unknown"
        )

        # -----------------------------------------
        # 4. Security headers
        # -----------------------------------------

        for header, description in SECURITY_HEADERS.items():

            if header in response.headers:

                result["security_headers"].append({
                    "name": header,
                    "status": "Present",
                    "description": description
                })

            else:

                result["missing_headers"].append({
                    "name": header,
                    "status": "Missing",
                    "description": description
                })

        # -----------------------------------------
        # 5. Cookies
        # -----------------------------------------

        for cookie in response.cookies:

            result["cookies"].append({
                "name": cookie.name,
                "secure": cookie.secure,
                "httponly": "HttpOnly" in cookie._rest,
                "samesite": cookie._rest.get("SameSite")
            })

        # -----------------------------------------
        # 6. Initial findings
        # -----------------------------------------

        if not result["https"]:

            result["findings"].append(
                create_finding(
                    title="HTTPS Not Detected",
                    severity="Medium",
                    description=(
                        "The target is not using HTTPS."
                    ),
                    evidence=(
                        f"Final URL: {response.url}"
                    ),
                    impact=(
                        "Data transmitted between the browser "
                        "and server may be exposed or modified "
                        "by an attacker."
                    ),
                    recommendation=(
                        "Configure HTTPS and redirect HTTP "
                        "traffic to HTTPS."
                    ),
                    owasp="A04: Cryptographic Failures"
                )
            )

        for header in result["missing_headers"]:

            result["findings"].append(
                create_finding(
                    title=(
                        f"Missing Security Header: "
                        f"{header['name']}"
                    ),
                    severity="Medium",
                    description=header["description"],
                    evidence=(
                        f"{header['name']} header was not "
                        f"present in the HTTP response."
                    ),
                    impact=(
                        "Missing security headers can reduce "
                        "the application's protection against "
                        "common browser-based attacks."
                    ),
                    recommendation=(
                        f"Configure the "
                        f"{header['name']} response header."
                    ),
                    owasp="A02: Security Misconfiguration"
                )
            )


                # -----------------------------------------
        # 6.1 Passive security checks
        # -----------------------------------------

        passive_findings = run_passive_checks(
            response,
            response.text
        )

        result["findings"].extend(
            passive_findings
        )


        # -----------------------------------------
        # 7. Crawl website
        # -----------------------------------------

        pages = crawl_target(
            session,
            response.url,
            max_pages=10
        )

        result["pages"] = pages

        result["total_pages"] = len(pages)

        # -----------------------------------------
        # 8. Collect discovered information
        # -----------------------------------------

        all_forms = []
        all_technologies = []
        all_parameters = []
        total_links = 0
        for page in pages:

            total_links += len(
                page["links"]
            )

            all_forms.extend(
                page["forms"]
            )

            all_technologies.extend(
                page["technologies"]
            )

            # Extract URL parameters
            parameters = get_url_parameters(
                page["url"]
            )

            for parameter in parameters:

                if parameter not in all_parameters:
                    all_parameters.append(parameter)

        result["total_links"] = total_links

        result["parameters"] = all_parameters

        result["forms"] = all_forms
        
        result["total_forms"] = len(
            all_forms
        )

        # -----------------------------------------
        # 8.1 Analyze input fields
        # -----------------------------------------

        analyzed_forms = analyze_forms(
            all_forms
        )

        result["interesting_inputs"] = (
            analyzed_forms
        )

        result["technologies"] = list(
            dict.fromkeys(
                all_technologies
            )
        )


        
        # -----------------------------------------
        # 8.2 Test URL parameters for reflected input
        # -----------------------------------------

        reflection_results = []

        for page in pages:

            page_parameters = get_url_parameters(
                page["url"]
            )

            for parameter in page_parameters:

                test_result = test_reflected_input(
                    session,
                    page["url"],
                    parameter
                )

                if test_result:

                    reflection_results.append(
                        test_result
                    )

                    # Create a finding only when the
                    # test marker appears in the response.
                    if test_result["reflected"]:

                        result["findings"].append(
                            create_finding(
                                title=(
                                    "Reflected Input Detected "
                                    "(Review Required)"
                                ),
                                severity="Informational",
                                description=(
                                    "A unique test marker supplied "
                                    "through a URL parameter was "
                                    "found in the HTTP response. "
                                    "This does not by itself prove "
                                    "a cross-site scripting (XSS) "
                                    "vulnerability."
                                ),
                                evidence=(
                                    f"Parameter: {parameter}; "
                                    f"HTTP status: "
                                    f"{test_result['status_code']}; "
                                    f"Marker: "
                                    f"{test_result['marker']}"
                                ),
                                impact=(
                                    "If user-controlled input is "
                                    "rendered without appropriate "
                                    "contextual output encoding, "
                                    "it may create a security risk."
                                ),
                                recommendation=(
                                    "Review the response context "
                                    "and verify that user input is "
                                    "properly encoded. Perform "
                                    "additional XSS validation "
                                    "only on an authorized test target."
                                ),
                                owasp="A05: Injection"
                            )
                        )

        result["reflection_tests"] = reflection_results
        

        # -----------------------------------------
        # 9. Cookie security findings
        # -----------------------------------------

        for cookie in result["cookies"]:

            if not cookie["secure"]:

                result["findings"].append(
                    create_finding(
                        title=(
                            f"Insecure Cookie: "
                            f"{cookie['name']}"
                        ),
                        severity="Medium",
                        description=(
                            "The cookie does not have "
                            "the Secure flag."
                        ),
                        evidence=(
                            f"Cookie '{cookie['name']}' "
                            f"was returned without the Secure flag."
                        ),
                        impact=(
                            "The cookie may be transmitted over "
                            "an unencrypted connection."
                        ),
                        recommendation=(
                            "Set the Secure flag on sensitive cookies."
                        ),
                        owasp="A02: Security Misconfiguration"
                    )
                )

            if not cookie["httponly"]:

                result["findings"].append(
                    create_finding(
                        title=(
                            f"Cookie Missing HttpOnly: "
                            f"{cookie['name']}"
                        ),
                        severity="Medium",
                        description=(
                            "The cookie does not have "
                            "the HttpOnly flag."
                        ),
                        evidence=(
                            f"Cookie '{cookie['name']}' "
                            f"was returned without the HttpOnly flag."
                        ),
                        impact=(
                            "Client-side scripts may be able to "
                            "access the cookie if a script injection "
                            "vulnerability exists."
                        ),
                        recommendation=(
                            "Set HttpOnly on cookies that do not "
                            "need client-side JavaScript access."
                        ),
                        owasp="A02: Security Misconfiguration"
                    )
                )

        return result

    except requests.exceptions.Timeout:

        result["error"] = (
            "The target took too long to respond."
        )

        return result

    except requests.exceptions.ConnectionError:

        result["error"] = (
            "Could not connect to the target."
        )

        return result

    except requests.exceptions.RequestException as error:

        result["error"] = (
            f"Request failed: {error}"
        )

        return result
