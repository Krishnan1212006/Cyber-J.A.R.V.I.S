"""
interview/api.py — FastAPI Router for Interview Question Generation & Voice Orchestration.
"""

from typing import List, Optional, Union
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from interview.models import (
    QuestionGenerationRequest,
    QuestionGenerationResponse,
    AdvancedQuestionRequest,
    VapiTurnTakingSettings,
    VapiTranscriberSettings,
    VapiVoiceSettings
)
from interview.question_service import QuestionGenerationService
from interview.voice_service import VoiceInterviewerService
from interview.config import (
    GROQ_MODEL,
    GROQ_TEMPERATURE,
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
    VAPI_PUBLIC_KEY
)

router = APIRouter(prefix="/api/interview", tags=["Interview Module"])

question_service = QuestionGenerationService()
voice_service = VoiceInterviewerService()


class CreateAssistantRequest(BaseModel):
    role: str
    level: str
    questions: List[str]
    tech_stack: Optional[Union[List[str], str]] = None
    voice_id: Optional[str] = None


class TurnInteractionRequest(BaseModel):
    role: str
    level: str
    current_question: str
    candidate_answer: str
    question_history: Optional[List[str]] = None


@router.post("/generate-questions", response_model=QuestionGenerationResponse)
async def generate_questions(request: QuestionGenerationRequest):
    """
    Module 1: Question Generation
    Receives role, level, tech stack, interview type, and question count.
    gpt-oss-120b on Groq at temperature 1.0 returns a JSON array of questions with no special characters.
    """
    try:
        result = question_service.generate_questions(request)
        return QuestionGenerationResponse(
            role=result["role"],
            level=result["level"],
            tech_stack=result["tech_stack"],
            interview_type=result["interview_type"],
            questions=result["questions"],
            model_used=result["model_used"],
            interview_id=result.get("interview_id")
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Question generation failed: {str(e)}")


@router.post("/advanced-questions", response_model=QuestionGenerationResponse)
async def advanced_questions(request: AdvancedQuestionRequest):
    """
    Advanced-question endpoint regenerates harder questions for an existing interview.
    """
    try:
        result = question_service.generate_advanced_questions(request)
        return QuestionGenerationResponse(
            role=result["role"],
            level=result["level"],
            tech_stack=result["tech_stack"],
            interview_type=result["interview_type"],
            questions=result["questions"],
            model_used=result["model_used"],
            interview_id=result.get("interview_id")
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Advanced question regeneration failed: {str(e)}")


@router.get("/voice-config")
async def get_voice_config(tech_stack: Optional[str] = None):
    """
    Returns the active specifications for:
    - Deepgram Nova-3 (en-IN, 400 ms endpointing, key-term boosting)
    - ElevenLabs voice model
    - 0.7 s base wait plus sigmoid smart-endpointing
    - Barge-in: 1 word, 0.4 s voice duration, 1.0 s back-off
    """
    stack_list = [t.strip() for t in tech_stack.split(",") if t.strip()] if tech_stack else None
    transcriber = voice_service.build_transcriber_config(stack_list)
    voice = voice_service.build_voice_config()
    turn_taking = voice_service.build_turn_taking_plans()

    return {
        "transcriber": transcriber,
        "voice": voice,
        "turn_taking": turn_taking,
        "vapi_public_key": VAPI_PUBLIC_KEY,
        "specs": {
            "stt_engine": f"Deepgram {DEEPGRAM_MODEL} ({DEEPGRAM_LANGUAGE})",
            "stt_endpointing_ms": DEEPGRAM_ENDPOINTING_MS,
            "tts_engine": f"ElevenLabs ({voice.get('voiceId')})",
            "base_wait_seconds": BASE_WAIT_SECONDS,
            "smart_endpointing": SMART_ENDPOINTING_TYPE,
            "barge_in": {
                "num_words": BARGE_IN_WORDS,
                "voice_duration_seconds": BARGE_IN_VOICE_DURATION,
                "backoff_seconds": BARGE_IN_BACKOFF_SECONDS
            }
        }
    }


@router.post("/create-assistant")
async def create_assistant(request: CreateAssistantRequest):
    """
    Module 2: Voice Interviewer and Turn-Taking
    Builds and registers Vapi assistant with warm professional persona,
    brief replies, follow-ups for vague answers, Deepgram Nova-3, ElevenLabs,
    and smart endpointing / barge-in plans.
    """
    try:
        tech_list = request.tech_stack
        if isinstance(tech_list, str):
            tech_list = [t.strip() for t in tech_list.split(",") if t.strip()]
        
        payload = voice_service.build_vapi_assistant_payload(
            role=request.role,
            level=request.level,
            questions=request.questions,
            tech_stack=tech_list,
            voice_id=request.voice_id
        )
        
        result = voice_service.create_or_register_vapi_assistant(payload)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed creating Vapi assistant: {str(e)}")


@router.post("/turn-interaction")
async def turn_interaction(req: TurnInteractionRequest):
    """
    Live turn-taking logic for spoken replies:
    Produces a warm professional reply (1-2 sentences), evaluating if the candidate's
    answer was vague, and giving an immediate follow-up probing edge cases or moving forward.
    """
    ans = req.candidate_answer.strip().lower()
    is_vague = (
        len(ans) < 25
        or any(w in ans for w in ["maybe", "i think so", "not sure", "depends on stuff", "use a library", "standard way"])
        or len(ans.split()) < 6
    )

    if is_vague:
        reply = (
            f"Understood. That touches on the surface, but could you dive deeper into the specific trade-offs, "
            f"such as failure recovery or latency implications in a high-traffic production system?"
        )
        status = "probe_followup"
    else:
        reply = (
            f"Excellent analysis. Your point on scalability and reliability makes solid engineering sense. "
            f"Let us build upon that for our next technical topic."
        )
        status = "progress"

    return {
        "status": status,
        "is_vague": is_vague,
        "spoken_reply": reply,
        "persona": "Warm Professional Interviewer (Brief 1-2 sentence response)",
        "next_action": "follow_up" if is_vague else "next_question"
    }
