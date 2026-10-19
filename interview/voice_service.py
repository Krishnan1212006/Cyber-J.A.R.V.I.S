"""
interview/voice_service.py — Module 2: Voice Interviewer and Turn-Taking.

Configures and manages Vapi assistant with:
- Warm professional persona with brief replies and follow-ups for vague candidate answers.
- Deepgram Nova-3 transcriber (en-IN, 400 ms endpointing, key-term boosting).
- ElevenLabs voice synthesis (pNInz6obpgDQGcFmaJgB / 21m00Tcm4TlvDq8ikWAM).
- 0.7 s base wait plus sigmoid smart-endpointing (startSpeakingPlan).
- Barge-in: 1 word, 0.4 s voice duration, 1.0 s back-off (stopSpeakingPlan).
"""

import json
from typing import Dict, List, Optional
import requests

from interview.config import (
    VAPI_API_KEY,
    VAPI_PUBLIC_KEY,
    DEEPGRAM_MODEL,
    DEEPGRAM_LANGUAGE,
    DEEPGRAM_ENDPOINTING_MS,
    ELEVENLABS_VOICE_ID,
    ELEVENLABS_MODEL,
    BASE_WAIT_SECONDS,
    SMART_ENDPOINTING_TYPE,
    BARGE_IN_WORDS,
    BARGE_IN_VOICE_DURATION,
    BARGE_IN_BACKOFF_SECONDS,
    GROQ_MODEL,
    GROQ_TEMPERATURE,
)


class VoiceInterviewerService:
    """Manages Vapi assistant payloads, turn-taking, and active voice session settings."""

    def __init__(self, vapi_api_key: str = VAPI_API_KEY, vapi_public_key: str = VAPI_PUBLIC_KEY):
        self.api_key = vapi_api_key or VAPI_API_KEY
        self.public_key = vapi_public_key or VAPI_PUBLIC_KEY

    def build_transcriber_config(self, tech_stack: Optional[List[str]] = None) -> dict:
        """
        Builds Deepgram Nova-3 transcriber configuration:
        - model: nova-3
        - language: en-IN
        - endpointing: 400 ms
        - keywords: key-term boosting based on candidate's tech stack
        """
        base_keywords = [
            "API:2", "latency:2", "throughput:2", "concurrency:2",
            "microservices:2", "scalability:2", "database:2", "caching:2",
            "asynchronous:2", "distributed:2", "Kubernetes:2", "Docker:2"
        ]
        if tech_stack:
            for tech in tech_stack:
                clean_t = tech.strip()
                if clean_t and f"{clean_t}:2" not in base_keywords:
                    base_keywords.append(f"{clean_t}:2")

        return {
            "provider": "deepgram",
            "model": DEEPGRAM_MODEL,
            "language": DEEPGRAM_LANGUAGE,
            "endpointing": DEEPGRAM_ENDPOINTING_MS,
            "keywords": base_keywords,
        }

    def build_voice_config(self, voice_id: Optional[str] = None) -> dict:
        """
        Builds ElevenLabs voice configuration:
        - provider: 11labs
        - voiceId: specified or configured ElevenLabs voice ID
        - model: eleven_turbo_v2_5 / eleven_multilingual_v2
        """
        chosen_voice = voice_id or ELEVENLABS_VOICE_ID or "pNInz6obpgDQGcFmaJgB"
        return {
            "provider": "11labs",
            "voiceId": chosen_voice,
            "model": ELEVENLABS_MODEL,
            "stability": 0.5,
            "similarityBoost": 0.75,
        }

    def build_turn_taking_plans(self) -> dict:
        """
        Builds turn-taking and interruption/barge-in plans:
        - 0.7 s base wait plus sigmoid smart-endpointing
        - Barge-in: needs 1 word, 0.4 s voice duration, 1.0 s back-off
        """
        start_speaking_plan = {
            "waitSeconds": BASE_WAIT_SECONDS,
            "smartEndpointingPlan": {
                "type": SMART_ENDPOINTING_TYPE
            }
        }

        stop_speaking_plan = {
            "numWords": BARGE_IN_WORDS,
            "voiceDuration": BARGE_IN_VOICE_DURATION,
            "backoffSeconds": BARGE_IN_BACKOFF_SECONDS
        }

        return {
            "startSpeakingPlan": start_speaking_plan,
            "stopSpeakingPlan": stop_speaking_plan
        }

    def build_system_prompt(self, role: str, level: str, questions: List[str]) -> str:
        """
        Generates system prompt enforcing:
        - Warm professional interviewer persona
        - Brief replies (maximum 2-3 sentences per turn)
        - Active probing and follow-ups when the candidate's answers are vague
        """
        questions_formatted = "\n".join(f"{i+1}. {q}" for i, q in enumerate(questions))
        
        prompt = (
            f"You are JARVIS, an empathetic, highly technical senior interviewer interviewing a candidate for a {level} {role} position.\n\n"
            "PERSONA & STYLE:\n"
            "1. Persona: Warm, encouraging, yet rigorous and deeply technical.\n"
            "2. Turn-Taking & Brevity: Keep your spoken replies CONCISE (1 to 2 sentences at most). Never deliver monologues.\n"
            "3. Follow-Ups for Vague Answers: If the candidate gives a shallow, vague, or high-level buzzword answer, ask a specific follow-up probing edge cases, bottlenecks, or implementation details before moving forward.\n"
            "4. Question Flow: Guide the candidate sequentially through the planned interview questions. Acknowledge their response warmly, probe deeper if needed, and smoothly introduce the next question.\n"
            "5. Tone: Conversational, clear enunciation for voice streaming.\n\n"
            f"PLANNED QUESTIONS FOR THIS INTERVIEW:\n{questions_formatted}\n\n"
            "Start by warmly welcoming the candidate and presenting the first question directly."
        )
        return prompt

    def build_vapi_assistant_payload(
        self,
        role: str,
        level: str,
        questions: List[str],
        tech_stack: Optional[List[str]] = None,
        voice_id: Optional[str] = None
    ) -> dict:
        """
        Builds the complete Vapi Assistant configuration object matching all required parameters.
        """
        first_q = questions[0] if questions else "Could you introduce your technical background and experience?"
        first_message = f"Hello! Welcome to your technical interview for the {level} {role} position. Let us begin. {first_q}"

        system_prompt = self.build_system_prompt(role, level, questions)
        plans = self.build_turn_taking_plans()
        transcriber = self.build_transcriber_config(tech_stack)
        voice = self.build_voice_config(voice_id)

        payload = {
            "name": f"JARVIS Interviewer - {level} {role}",
            "model": {
                "provider": "groq",
                "model": GROQ_MODEL,
                "temperature": GROQ_TEMPERATURE,
                "messages": [
                    {"role": "system", "content": system_prompt}
                ]
            },
            "voice": voice,
            "transcriber": transcriber,
            "startSpeakingPlan": plans["startSpeakingPlan"],
            "stopSpeakingPlan": plans["stopSpeakingPlan"],
            "firstMessage": first_message,
            "silenceTimeoutSeconds": 30,
            "maxDurationSeconds": 1800,
            "backgroundSound": "off"
        }
        return payload

    def create_or_register_vapi_assistant(self, payload: dict) -> dict:
        """
        Sends assistant payload to Vapi REST API (https://api.vapi.ai/assistant)
        if VAPI_API_KEY is available, or returns payload ready for client-side Vapi Web SDK.
        """
        if not self.api_key:
            return {
                "status": "configured_offline",
                "assistant_id": "vapi_simulated_assistant",
                "assistant": payload,
                "public_key": self.public_key,
                "message": "Assistant payload generated with Deepgram Nova-3, ElevenLabs, and Turn-Taking settings. Provide VAPI_API_KEY to persist to Vapi Cloud."
            }

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

        try:
            resp = requests.post("https://api.vapi.ai/assistant", json=payload, headers=headers, timeout=15)
            if resp.status_code in (200, 201):
                data = resp.json()
                return {
                    "status": "created",
                    "assistant_id": data.get("id"),
                    "assistant": data,
                    "public_key": self.public_key
                }
            else:
                return {
                    "status": "api_error",
                    "status_code": resp.status_code,
                    "error": resp.text,
                    "assistant": payload,
                    "public_key": self.public_key
                }
        except Exception as e:
            return {
                "status": "network_exception",
                "error": str(e),
                "assistant": payload,
                "public_key": self.public_key
            }
