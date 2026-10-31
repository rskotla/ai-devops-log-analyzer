import os
import sys

from dotenv import load_dotenv
from azure.identity import DefaultAzureCredential
from azure.ai.projects import AIProjectClient

load_dotenv()

PROJECT_ENDPOINT = os.getenv("AZURE_AI_PROJECT_ENDPOINT")
DEPLOYMENT_NAME = os.getenv("AZURE_AI_DEPLOYMENT_NAME")


class AzureAIAnalyzer:
    """Azure AI Foundry GPT deployment provider."""

    def __init__(self):
        if not PROJECT_ENDPOINT:
            raise ValueError("AZURE_AI_PROJECT_ENDPOINT missing in .env")

        if not DEPLOYMENT_NAME:
            raise ValueError("AZURE_AI_DEPLOYMENT_NAME missing in .env")

        self.credential = DefaultAzureCredential()
        self.project_client = AIProjectClient(
            endpoint=PROJECT_ENDPOINT,
            credential=self.credential,
        )
        self.openai_client = self.project_client.get_openai_client()

    def analyze(self, prompt: str) -> str:
        if not prompt or not prompt.strip():
            raise ValueError("Prompt cannot be empty")

        response = self.openai_client.responses.create(
            model=DEPLOYMENT_NAME,
            input=prompt,
        )

        if not response.output_text:
            raise RuntimeError("Azure returned an empty response")

        return response.output_text

    def close(self):
        try:
            self.openai_client.close()
        finally:
            try:
                self.project_client.close()
            finally:
                self.credential.close()


def main():
    prompt = " ".join(sys.argv[1:]).strip()

    if not prompt:
        prompt = "Explain why Kubernetes pods restart."

    analyzer = None

    try:
        analyzer = AzureAIAnalyzer()
        print("\n========== AZURE AI ANALYSIS ==========\n")
        print(analyzer.analyze(prompt))
        print("\n=======================================\n")

    except Exception as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(1)

    finally:
        if analyzer:
            analyzer.close()


if __name__ == "__main__":
    main()
