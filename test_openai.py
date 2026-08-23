import os

from dotenv import load_dotenv
from openai import OpenAI


load_dotenv()


model = os.getenv("OPENAI_MODEL")

client = OpenAI()


response = client.responses.create(
    model=model,
    input="Reply with exactly: API WORKS"
)


print(response.output_text)