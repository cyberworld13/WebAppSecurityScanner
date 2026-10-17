import requests

from urllib.parse import urlparse, parse_qsl

def get_url_parameters(url):
    """
    Extract query-string parameters from a URL.
    """

    parsed = urlparse(url)

    parameters = parse_qsl(
        parsed.query,
        keep_blank_values=True
    )

    return [
        name
        for name, value in parameters
    ]


def analyze_forms(forms):
    """
    Analyze discovered forms and identify
    potentially interesting input fields.
    """

    results = []

    interesting_names = [
        "id",
        "user",
        "username",
        "email",
        "search",
        "query",
        "q",
        "url",
        "redirect",
        "page",
        "file",
        "path",
        "name",
        "message",
        "comment"
    ]

    for form in forms:

        interesting_fields = []

        for field in form.get("inputs", []):

            field_name = field.get(
                "name",
                ""
            ).lower()

            if field_name in interesting_names:

                interesting_fields.append({
                    "name": field.get("name"),
                    "type": field.get("type", "text")
                })

        results.append({
            "action": form.get("action"),
            "method": form.get("method"),
            "interesting_fields": interesting_fields
        })

    return results


def test_reflected_input(session, url, parameter):
    """
    Test whether a URL parameter is reflected
    in a successful HTTP response.
    """

    marker = "SCAN_MARKER_7F3A"

    parsed = urlparse(url)

    parameters = dict(
        parse_qsl(
            parsed.query,
            keep_blank_values=True
        )
    )

    if parameter not in parameters:
        return None

    parameters[parameter] = marker

    try:
        response = session.get(
            url,
            params=parameters,
            timeout=10,
            allow_redirects=True
        )

        # Do not report reflections from rate-limited
        # or unsuccessful HTTP responses.
        if response.status_code == 429:
            return {
                "parameter": parameter,
                "url": response.url,
                "marker": marker,
                "reflected": False,
                "status_code": 429,
                "skipped": True,
                "reason": "Target returned HTTP 429 (Too Many Requests)."
            }

        if not 200 <= response.status_code < 300:
            return {
                "parameter": parameter,
                "url": response.url,
                "marker": marker,
                "reflected": False,
                "status_code": response.status_code,
                "skipped": True,
                "reason": "Target returned an unsuccessful HTTP response."
            }

        reflected = marker in response.text

        return {
            "parameter": parameter,
            "url": response.url,
            "marker": marker,
            "reflected": reflected,
            "status_code": response.status_code
        }

    except requests.RequestException:
        return None
    