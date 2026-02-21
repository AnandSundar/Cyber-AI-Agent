"""
This module demonstrates a simple interaction with the OpenAI API to generate a recipe.
"""

# API Keys: https://platform.openai.com/settings/organization/api-keys
# Billing:  https://platform.openai.com/settings/organization/billing/overview

import os
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()


openai_client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

PROMPT = "Give me a very short recipe for a cake please."

response = openai_client.chat.completions.create(
    model="gpt-5", messages=[{"role": "user", "content": PROMPT}]
)

answer = response.choices[0].message.content

print(f"\n{answer}\n")
