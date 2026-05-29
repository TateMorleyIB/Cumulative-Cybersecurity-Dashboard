import requests
from dotenv import load_dotenv
import urllib3
import json
from app.config import BITSIGHT_API_KEY
from pathlib import Path
from datetime import datetime, timedelta

PROJECT_ROOT = Path(__file__).resolve().parents[2]

CACHE_FILE = PROJECT_ROOT / "data" / "raw" / "bitsight" / "bitsight_companies.json"
LOGO_CACHE_FILE = PROJECT_ROOT / "data" / "raw" / "bitsight" / "bitsight_logo.png"
SPARKLINE_CACHE_FILE = (
    PROJECT_ROOT / "data" / "raw" / "bitsight" / "bitsight_sparkline.png"
)

CACHE_TTL = timedelta(hours=24)

# Disable annoying warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

load_dotenv()


class BitSightConnector:
    """
    Client for collecting and caching BitSight company rating assets.

    The connector owns authentication, local cache paths, company metadata lookup, and small binary assets such as the logo and sparkline used by the HTML dashboards.
    """

    BASE_URL = "https://api.bitsighttech.com/ratings/v1"

    def __init__(self):
        """Create an authenticated BitSight requests session.

        The connector uses HTTP basic authentication where the API key is the
        username and the password is blank, matching BitSight's ratings API
        convention. The session also installs a default JSON ``Accept`` header
        for metadata requests; image endpoints override that header locally.

        Raises:
            ValueError: Raised when ``BITSIGHT_API_KEY`` is not configured.
        """
        if not BITSIGHT_API_KEY:
            raise ValueError("BITSIGHT_API_KEY is missing from .env")

        # Create session with necessary authentication
        self.session = requests.Session()
        self.session.auth = (BITSIGHT_API_KEY, "")

        # Set default headers
        self.session.headers.update({"Accept": "application/json"})

    def get_company(self):
        """Return the primary company record from the BitSight companies payload.

        BitSight returns a top-level ``companies`` collection. The dashboard is
        scoped to the first company associated with the configured API key, so
        this helper centralizes the extraction and empty-list handling.

        Returns:
            dict | None: First company dictionary when present; otherwise
            ``None`` when BitSight returns no companies.
        """
        data = self.get_companies_data()
        companies = data.get("companies", [])

        if not companies:
            return None

        return companies[0]

    def get_company_guid(self):
        """Return the BitSight GUID for the primary company.

        The GUID is required for company-specific asset endpoints such as the
        logo and sparkline image routes.

        Returns:
            str | None: Company GUID when a primary company is available;
            otherwise ``None``.
        """
        company = self.get_company()

        if not company:
            return None

        return company.get("guid")

    def get_company_logo_image(self):
        """Fetch and cache the BitSight company logo image.

        A fresh cached logo is served from disk to avoid unnecessary binary API
        requests. When the cache is missing or stale, the method resolves the
        primary company GUID, downloads the logo-image endpoint, writes it to
        the BitSight raw-data cache directory, and returns the bytes for the
        FastAPI image route.

        Returns:
            tuple[bytes | None, str | None]: Image bytes and content type when
            available; ``(None, None)`` when no company GUID can be resolved.

        Raises:
            requests.HTTPError: Raised when BitSight returns an unsuccessful
            status for the logo image request.
        """
        if LOGO_CACHE_FILE.exists():
            modified_time = datetime.fromtimestamp(LOGO_CACHE_FILE.stat().st_mtime)
            if datetime.now() - modified_time < CACHE_TTL:
                print("Using cached logo")
                with open(LOGO_CACHE_FILE, "rb") as file:
                    return file.read(), "image/png"

        print("Calling BitSight logo API")

        guid = self.get_company_guid()
        if not guid:
            return None, None

        url = f"{self.BASE_URL}/companies/{guid}/logo-image"
        response = self.session.get(
            url, timeout=30, verify=False, headers={"Accept": "image/*"}
        )

        print("Logo status:", response.status_code)
        print("Logo content type:", response.headers.get("Content-Type"))
        print("Logo first bytes:", response.content[:20])

        response.raise_for_status()

        content_type = response.headers.get("Content-Type", "image/png")

        LOGO_CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)

        with open(LOGO_CACHE_FILE, "wb") as file:
            file.write(response.content)

        return response.content, content_type

    def get_company_sparkline_image(self):
        """Fetch and cache the BitSight rating trend sparkline image.

        A fresh cached sparkline is served from disk to avoid unnecessary binary
        API requests. When the cache is missing or stale, the method resolves
        the primary company GUID and downloads the small sparkline image. The
        frontend renders the ``/bitsight/sparkline`` route with explicit
        ``width=60`` and ``height=20`` attributes plus matching CSS so the image
        remains aligned in compact desktop dashboard tiles.

        Returns:
            tuple[bytes | None, str | None]: Sparkline bytes and content type
            when available; ``(None, None)`` when no company GUID can be
            resolved.

        Raises:
            requests.HTTPError: Raised when BitSight returns an unsuccessful
            status for the sparkline request.
        """
        if SPARKLINE_CACHE_FILE.exists():
            modified_time = datetime.fromtimestamp(SPARKLINE_CACHE_FILE.stat().st_mtime)
            if datetime.now() - modified_time < CACHE_TTL:
                print("Using cached sparkline")
                with open(SPARKLINE_CACHE_FILE, "rb") as file:
                    return file.read(), "image/png"

        print("Calling BitSight sparkline API")

        guid = self.get_company_guid()
        if not guid:
            return None, None

        url = f"{self.BASE_URL}/companies/{guid}/sparkline?size=small"

        response = self.session.get(
            url, timeout=30, verify=False, headers={"Accept": "image/*"}
        )

        print("Sparkline status:", response.status_code)
        print("Sparkline content type:", response.headers.get("Content-Type"))
        print("Sparkline first bytes:", response.content[:20])

        response.raise_for_status()

        content_type = response.headers.get("Content-Type", "image/png")

        SPARKLINE_CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)

        with open(SPARKLINE_CACHE_FILE, "wb") as file:
            file.write(response.content)

        return response.content, content_type

    def get_companies_data(self):
        """Read or refresh the BitSight companies metadata payload.

        The metadata cache stores the ``/companies`` response under
        ``data/raw/bitsight``. Cached data is reused while it is younger than
        ``CACHE_TTL``; otherwise, the method fetches a new payload from BitSight
        and rewrites the cache file.

        Returns:
            dict: Decoded BitSight companies response.

        Raises:
            requests.HTTPError: Raised when BitSight returns an unsuccessful
            status for the companies request.
            json.JSONDecodeError: Raised if a fresh cache file cannot be parsed.
        """

        if CACHE_FILE.exists():
            modified_time = datetime.fromtimestamp(CACHE_FILE.stat().st_mtime)
            time_since_last_cache = datetime.now() - modified_time

            if time_since_last_cache < CACHE_TTL:
                with open(CACHE_FILE, "r") as file:
                    return json.load(file)

        url = f"{self.BASE_URL}/companies"

        response = self.session.get(url, timeout=30, verify=False)
        response.raise_for_status()

        data = response.json()

        CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)

        with open(CACHE_FILE, "w") as file:
            json.dump(data, file, indent=4)

        return data

    def get_company_summary(self):
        """Build dashboard-ready BitSight company summary data.

        The summary flattens the cached or freshly fetched companies payload
        into the fields used by the master dashboard and BitSight detail page,
        including rating score, rating dates, display URL, logo metadata, and
        sparkline metadata.

        Returns:
            dict[str, object] | None: Summary fields for the primary company,
            or ``None`` when the companies payload contains no company records.
        """
        data = self.get_companies_data()
        companies = data.get("companies", [])

        if not companies:
            print('Error fetching "companies" dictionary list')
            return None
        company = companies[0]

        # Data variables
        name = company.get("name")
        score = company.get("rating")
        rating_date = data.get("rating_date")
        rating_since = data.get("created")
        company_url = company.get("display_url")
        company_logo = company.get("logo")
        sparkline_graph = company.get("sparkline")

        # Summary dictionary
        summary = {
            "name": name,
            "score": score,
            "rating_date": rating_date,
            "rating_since": rating_since,
            "company_url": company_url,
            "logo": company_logo,
            "sparkline": sparkline_graph,
        }

        return summary


if __name__ == "__main__":
    connector = BitSightConnector()
    result = connector.test_connection()
    print(result)
