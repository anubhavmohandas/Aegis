"""
Turns a MonitorEvent into a plain-English explanation using any OpenAI-compatible
endpoint (NVIDIA Build, OpenAI, OpenRouter, a local Ollama, ...) or Anthropic's
native API. Which one answers is decided entirely by config -- this module only
knows two API *shapes*, never individual vendors.

IMPORTANT LIMITATION (read this before relying on it):
This is a convenience/UX layer, NOT a security verdict. The model has no
ground-truth threat intelligence, no access to VirusTotal/hash reputation,
and can be wrong or hallucinate a risk assessment in either direction. Treat
its "likely normal" / "worth checking" output as a first-pass explanation for
a human, not an automated decision. Every event is still logged to disk
in full regardless of what the AI says, so nothing is silently dropped.
"""

from __future__ import annotations

import logging

from .config import AppConfig
from .events import MonitorEvent

logger = logging.getLogger("aegis.ai_explainer")

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
        else:
            # Everything that isn't Anthropic speaks the OpenAI wire format;
            # base_url alone decides who actually answers.
            import openai
            self._client = openai.OpenAI(
                base_url=self.config.ai_base_url,
                api_key=self.config.api_key,
            )
        return self._client

    def explain(self, event: MonitorEvent, severity: str = "medium") -> str:
        if not self.config.api_key:
            return (
                f"[No API key configured] Raw event: {event.summary}\n"
                f"Set {self.config.ai_api_key_env} to get AI explanations."
            )

        prompt = event.as_prompt_block() + f"\nLocally-computed severity: {severity}"
        try:
            if self.config.ai_provider == "anthropic":
                return self._explain_anthropic(prompt)
            else:
                return self._explain_openai_compatible(prompt)
        except Exception as e:
            # Never let an AI/network failure crash the monitor loop -- fall back
            # to the raw event so the user still gets *something* useful.
            #
            # The raw exception is logged (console only) but deliberately NOT put
            # into the returned string -- that string ends up in a desktop
            # notification banner and the persisted timeline, both of which are
            # more exposed than a log file. Provider client errors can echo back
            # things like partial API keys, internal URLs, or proxy config in
            # their message text; there's no reason to surface that to whoever's
            # glancing at a notification.
            logger.error("AI explainer failed for event %r: %s", event.summary, e)
            return f"[AI explainer unavailable -- see logs] Raw event: {event.summary}"

    def _explain_anthropic(self, prompt: str) -> str:
        client = self._get_client()
        resp = client.messages.create(
            model=self.config.ai_model,
            max_tokens=300,
            temperature=self.config.ai_temperature,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )
        return resp.content[0].text

    def _explain_openai_compatible(self, prompt: str) -> str:
        client = self._get_client()
        resp = client.chat.completions.create(
            model=self.config.ai_model,
            max_tokens=300,
            temperature=self.config.ai_temperature,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
        )
        return resp.choices[0].message.content
