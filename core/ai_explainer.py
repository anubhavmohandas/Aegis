"""
Turns a MonitorEvent into a plain-English explanation using Claude or OpenAI.

IMPORTANT LIMITATION (read this before relying on it):
This is a convenience/UX layer, NOT a security verdict. The model has no
ground-truth threat intelligence, no access to VirusTotal/hash reputation,
and can be wrong or hallucinate a risk assessment in either direction. Treat
its "likely normal" / "worth checking" output as a first-pass explanation for
a human, not an automated decision. Every event is still logged to disk
in full regardless of what the AI says, so nothing is silently dropped.
"""

from __future__ import annotations

from .config import AppConfig
from .events import MonitorEvent

SYSTEM_PROMPT = """You are a plain-English security explainer for a personal desktop \
monitoring tool. You will be given a single system event (a new process starting, a USB \
device being connected, a startup program being added, or a file change in a watched folder).

Respond in 3 short parts, no more than 4 sentences total:
1. What happened, in plain English (no jargon).
2. Your best-effort read: "likely normal", "worth a quick look", or "unusual, investigate now".
3. One concrete next step the user could take if they want to check further.

If you are not confident, say so explicitly instead of guessing a verdict. You are not an \
antivirus and have no access to threat intelligence feeds -- do not imply otherwise.

You will also be told a locally-computed severity level (low/medium/high/critical). This came \
from a deterministic heuristic, not from you -- treat it as one input, not a fact to defer to. \
You may agree, disagree, or add nuance to it in your explanation."""


class AIExplainer:
    def __init__(self, config: AppConfig):
        self.config = config
        self._client = None

    def _get_client(self):
        if self._client is not None:
            return self._client
        if self.config.ai_provider == "anthropic":
            import anthropic
            self._client = anthropic.Anthropic(api_key=self.config.api_key)
        elif self.config.ai_provider == "openai":
            import openai
            self._client = openai.OpenAI(api_key=self.config.api_key)
        else:
            raise ValueError(f"Unknown ai_provider: {self.config.ai_provider}")
        return self._client

    def explain(self, event: MonitorEvent, severity: str = "medium") -> str:
        if not self.config.api_key:
            return (
                f"[No API key configured] Raw event: {event.summary}\n"
                f"Set ANTHROPIC_API_KEY or OPENAI_API_KEY to get AI explanations."
            )

        prompt = event.as_prompt_block() + f"\nLocally-computed severity: {severity}"
        try:
            if self.config.ai_provider == "anthropic":
                return self._explain_anthropic(prompt)
            else:
                return self._explain_openai(prompt)
        except Exception as e:
            # Never let an AI/network failure crash the monitor loop -- fall back
            # to the raw event so the user still gets *something* useful.
            return f"[AI explainer failed: {e}]\nRaw event: {event.summary}"

    def _explain_anthropic(self, prompt: str) -> str:
        client = self._get_client()
        resp = client.messages.create(
            model=self.config.ai_model,
            max_tokens=300,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )
        return resp.content[0].text

    def _explain_openai(self, prompt: str) -> str:
        client = self._get_client()
        resp = client.chat.completions.create(
            model=self.config.ai_model,
            max_tokens=300,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
        )
        return resp.choices[0].message.content
