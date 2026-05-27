import os
import google.auth
from pydantic import BaseModel, Field
from google.adk.agents import Agent
from google.adk.apps import App
from google.adk.models import Gemini
from google.genai import types

# Set up GCP environment
_, project_id = google.auth.default()
os.environ["GOOGLE_CLOUD_PROJECT"] = project_id
os.environ["GOOGLE_CLOUD_LOCATION"] = "us-east1"
os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "True"

class DomainAnalysis(BaseModel):
    analysis_summary: str = Field(description="A concise, tactical summary of the domain's security posture and identified assets.")
    exploitation_suggestions: str = Field(description="A detailed list of potential exploitation paths, vulnerabilities, or further research steps in Markdown format.")

instruction = """
You are a senior cybersecurity analyst and penetration tester. 
Your task is to review reconnaissance data for a target domain and provide a professional, tactical analysis.

Reconnaissance data includes:
- Subdomains and their associated IPs
- Open ports and services (service name, software version, etc.)
- Web application technology stacks
- WHOIS and ownership information

Based on this data, you must provide:
1. **Analysis Summary**: A high-level overview of the target's external attack surface. Highlight interesting technologies, clusters of assets, or any obvious misconfigurations.
2. **Exploitation Suggestions**: Actionable steps for a penetration tester. This should include specific tools to use (e.g., nmap, nuclei, ffuf), specific ports to investigate, and potential vulnerabilities based on identified software versions. Use Markdown for formatting.

Be professional, concise, and technical.
"""

root_agent = Agent(
    name="domain_analyst",
    model=Gemini(
        model="gemini-2.5-flash", # Using Flash for speed and efficiency
        retry_options=types.HttpRetryOptions(attempts=3),
    ),
    instruction=instruction,
    output_schema=DomainAnalysis,
    output_key="analysis"
)

app = App(
    root_agent=root_agent,
    name="domain_analyst_agent",
)
