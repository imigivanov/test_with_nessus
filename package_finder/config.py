import os
from dotenv import load_dotenv

load_dotenv('.env')


SECRET_KEY = os.getenv("SECRET_KEY")
ACCESS_KEY = os.getenv("ACCESS_KEY")
