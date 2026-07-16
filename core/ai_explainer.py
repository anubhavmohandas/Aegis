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

# When the enrichment stage (core/enrichment.py) attached evidence, the
# "you have no threat intelligence" line above becomes a lie -- swap exactly
# that sentence for instructions on how to use the evidence without
# over-trusting it in either direction.
_NO_INTEL_SENTENCE = ("You are not an antivirus and have no access to threat intelligence "
                       "feeds -- do not imply otherwise.")
_INTEL_SENTENCE = (
    "This event includes a threat_intel block: structured facts from a VirusTotal hash lookup "
    "and/or local MITRE ATT&CK annotations, fetched by the tool -- NOT your inference. Cite those "
    "numbers exactly; never invent detections, family names, or technique ids beyond what the "
    "block contains. Zero detections or an unknown hash is NOT evidence the file is safe (new "
    "malware is often undetected at first) -- say so explicitly when relevant. You are still not "
    "an antivirus; the evidence informs your read, it does not replace the user's judgment."
)
assert _NO_INTEL_SENTENCE in SYSTEM_PROMPT, "SYSTEM_PROMPT drifted -- update _NO_INTEL_SENTENCE to match"
SYSTEM_PROMPT_WITH_INTEL = SYSTEM_PROMPT.replace(_NO_INTEL_SENTENCE, _INTEL_SENTENCE)

REPORT_SYSTEM_PROMPT = """You are writing the executive summary section of a personal desktop \
security activity report, covering everything a monitoring tool observed over a given time \
period. You will be given aggregate stats (event counts by severity/source/category) and a \
list of the highest-severity events from the period.

Write in this exact structure, plain text (no markdown headers, may use "- " bullets):

Overview: 2-3 sentences summarizing overall activity level and whether anything stands out.
Notable events: up to 4 bullets, each one specific event or pattern worth the user's attention
  (skip this section entirely -- write nothing -- if nothing rises above routine background
  activity).
Recommendation: 1-2 sentences of concrete next steps, or a brief reassurance if nothing needs
  action.

Be honest about uncertainty and never claim to be an antivirus or threat-intel source -- you are \
summarizing locally-computed severity heuristics and prior AI explanations, not issuing a \
verdict. Keep the whole thing under 180 words. Plain English, no jargon."""

AWAY_SYSTEM_PROMPT = """You are briefing a computer's owner on what happened WHILE THEY WERE AWAY \
(the screen was locked). You will be given how long they were away and the list of system events \
that occurred during that window, in time order.

Write a short briefing, plain text (no markdown headers, may use "- " bullets):

Start with one sentence: how long they were away and the overall activity level.
Then, if anything is worth their attention (a USB device connected, an app installed, a new \
startup item, an executable run from Downloads/Temp, files deleted), call it out as a short \
bulleted story in the order it happened. If nothing rises above routine background activity, say \
so plainly and reassuringly instead of inventing concern.
End with one line: whether any of it deserves a closer look, and if so, the single most useful \
next step.

You are summarizing locally-detected events, not issuing a security verdict, and you are not an \
antivirus. Under 160 words. If there were no events at all, just say the machine was quiet."""

INCIDENT_SYSTEM_PROMPT = """You are writing a one-paragraph incident summary for a personal \
security tool's owner. Someone made repeated failed attempts to perform a protected action (such \
as stopping monitoring) on the owner's computer, and the tool captured evidence in response.

You will be given the incident reason, the number of failed attempts, which evidence artifacts \
were captured, the active application at capture time, and recent process/network context.

Write ONE short factual paragraph (under 90 words): what happened, what was captured, and -- only \
if the context genuinely warrants it -- one calm next step for the owner. State only what the \
provided facts support; do not speculate about who it was or their intent. Plain English."""


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
        system_prompt = SYSTEM_PROMPT_WITH_INTEL if "threat_intel" in event.details else SYSTEM_PROMPT
        try:
            if self.config.ai_provider == "anthropic":
                return self._explain_anthropic(prompt, event.summary, system_prompt)
            else:
                return self._explain_openai_compatible(prompt, event.summary, system_prompt)
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

    @staticmethod
    def _nonempty(text, fallback_summary: str) -> str:
        # An OpenAI-compatible endpoint can legally return `content: null`
        # (e.g. a refusal or a filtered response), and Anthropic can return an
        # empty content list -- neither raises, so explain()'s except clause
        # never sees them. A None explanation used to flow straight into
        # notify() (where len(None) raised) and into the timeline as an empty
        # explanation. Coerce to the same style of honest fallback string that
        # actual API errors already produce.
        if text:
            return text
        return f"[AI returned an empty response] Raw event: {fallback_summary}"

    def _explain_anthropic(self, prompt: str, event_summary: str, system_prompt: str = SYSTEM_PROMPT) -> str:
        client = self._get_client()
        resp = client.messages.create(
            model=self.config.ai_model,
            max_tokens=300,
            temperature=self.config.ai_temperature,
            system=system_prompt,
            messages=[{"role": "user", "content": prompt}],
        )
        text = resp.content[0].text if resp.content else None
        return self._nonempty(text, event_summary)

    def _explain_openai_compatible(self, prompt: str, event_summary: str, system_prompt: str = SYSTEM_PROMPT) -> str:
        client = self._get_client()
        resp = client.chat.completions.create(
            model=self.config.ai_model,
            max_tokens=300,
            temperature=self.config.ai_temperature,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt},
            ],
        )
        return self._nonempty(resp.choices[0].message.content, event_summary)

    def _summarize(self, system_prompt: str, user_block: str, fallback: str,
                   max_tokens: int = 400) -> str:
        """Shared narrative path for every whole-window summary (period
        report, away-session recap, incident). Same client/provider
        resolution and same never-surface-the-raw-exception rule as
        explain(); only the system prompt and the input block differ."""
        if not self.config.api_key:
            return f"[No AI summary -- {self.config.ai_api_key_env} is not set] {fallback}"
        try:
            client = self._get_client()
            if self.config.ai_provider == "anthropic":
                resp = client.messages.create(
                    model=self.config.ai_model, max_tokens=max_tokens,
                    temperature=self.config.ai_temperature, system=system_prompt,
                    messages=[{"role": "user", "content": user_block}],
                )
                text = resp.content[0].text if resp.content else None
                return self._nonempty(text, fallback)
            resp = client.chat.completions.create(
                model=self.config.ai_model, max_tokens=max_tokens,
                temperature=self.config.ai_temperature,
                messages=[{"role": "system", "content": system_prompt},
                          {"role": "user", "content": user_block}],
            )
            return self._nonempty(resp.choices[0].message.content, fallback)
        except Exception as e:
            logger.error("AI summary failed (%s): %s", system_prompt[:32], e)
            return f"[AI summary unavailable -- see logs] {fallback}"

    def summarize_period(self, stats_block: str) -> str:
        """Executive-summary narrative for the PDF activity report (see
        core/report_generator.py)."""
        return self._summarize(REPORT_SYSTEM_PROMPT, stats_block,
                               "The stats and event table below are unaffected.")

    def summarize_away(self, away_block: str) -> str:
        """Plain-English recap of what happened while the screen was locked
        (see core/dispatcher._attach_away_recap)."""
        return self._summarize(AWAY_SYSTEM_PROMPT, away_block,
                               "See the timeline for what happened while you were away.", max_tokens=350)

    def summarize_incident(self, incident_block: str) -> str:
        """One-paragraph tamper-incident summary (see core/evidence.py)."""
        return self._summarize(INCIDENT_SYSTEM_PROMPT, incident_block,
                               "See the incident record for the captured evidence.", max_tokens=250)
