from dotenv import load_dotenv
import os

load_dotenv()

CROWDSTRIKE_CLIENT_ID = os.getenv("CROWDSTRIKE_CLIENT_ID")
CROWDSTRIKE_SECRET = os.getenv("CROWDSTRIKE_SECRET")

ABNORMAL_API_KEY = os.getenv("ABNORMAL_API_KEY")

DELINEA_API_KEY = os.getenv("DELINEA_API_KEY")

BITSIGHT_API_KEY = os.getenv("BITSIGHT_API_KEY")
