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
SPARKLINE_CACHE_FILE = PROJECT_ROOT / "data" / "raw" / "bitsight" / "bitsight_sparkline.png"

CACHE_TTL  = timedelta(hours=24)

# Disable annoying warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

load_dotenv()

class BitSightConnector:
    BASE_URL = "https://api.bitsighttech.com/ratings/v1"

    def __init__(self):
        """Creates the session and sets up API key handling

        Raises:
            ValueError: Checks if BitSight API key is present in the .env
        """
        if not BITSIGHT_API_KEY:
            raise ValueError("BITSIGHT_API_KEY is missing from .env")

        # Create session with necessary authentication
        self.session = requests.Session()
        self.session.auth = (BITSIGHT_API_KEY, "")

        # Set default headers
        self.session.headers.update({
            "Accept": "application/json"
        })
        
    def get_company(self):
        """Organizes fetched data to gather just the company information

        Returns:
            [Dict]: A list of company dictionaries
        """
        data = self.get_companies_data()
        companies = data.get("companies", [])

        if not companies:
            return None

        return companies[0]


    def get_company_guid(self):
        """Returns only the company's guid value

        Returns:
            int: The guid value for the company, which may be used for further calls
        """
        company = self.get_company()

        if not company:
            return None

        return company.get("guid")


    def get_company_logo_image(self):
        """Fetches the company logo and caches it for use in frontend presentation

        Returns:
            File: The logo image file
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
            url,
            timeout=30,
            verify=False,
            headers={"Accept": "image/*"}
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
        """Fetches the company's rating trend sparkline and caches it.

        The UI renders this image through the /bitsight/sparkline route with
        explicit 60x20 dimensions so the small API image stays aligned in
        desktop dashboard tiles.

        Returns:
            File: The sparkline image file
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
            url,
            timeout=30,
            verify=False,
            headers={"Accept": "image/*"}
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
        """
        Uses cached data from data/raw/bitsight_companies.json if it is less
        than 24 hours old. Otherwise, pulls fresh data from BitSight and updates
        cache.

        Returns:
            JSON: The company data
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
        """Gathers all data needed from BitSight to be used and displayed in other places.
    
        Returns:
            JSON: the datapoints to summarize gitsight functionality
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
            "sparkline": sparkline_graph
        }
        
        return summary
   
if __name__ == "__main__":
    connector = BitSightConnector()
    result = connector.test_connection()
    print(result)