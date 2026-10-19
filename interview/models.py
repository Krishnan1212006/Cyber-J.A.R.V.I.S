"""
interview/models.py — Data models for Question Generation & Vapi Voice Interviewer.
"""

from typing import List, Optional, Union
from pydantic import BaseModel, Field


class QuestionGenerationRequest(BaseModel):
    role: str = Field(..., description="Target job role, e.g. 'Senior Backend Engineer'")
    level: str = Field(..., description="Seniority level, e.g. 'Junior', 'Mid-Level', 'Senior', 'Staff'")
    tech_stack: Union[List[str], str] = Field(..., description="List of technologies or comma-separated string")
    interview_type: str = Field(default="Technical Deep Dive", description="Type: 'System Design', 'Technical Deep Dive', 'Coding / Architecture', 'Behavioral'")
    question_count: int = Field(default=5, ge=1, le=20, description="Number of questions to generate")


class QuestionGenerationResponse(BaseModel):
    role: str
    level: str
    tech_stack: List[str]
    interview_type: str
    questions: List[str]
    model_used: str
    interview_id: Optional[str] = None


class AdvancedQuestionRequest(BaseModel):
    interview_id: Optional[str] = None
    role: str
    level: str
    tech_stack: Union[List[str], str]
    previous_questions: List[str] = Field(default_factory=list)
    candidate_answers: Optional[List[str]] = Field(default=None)
    question_count: int = Field(default=3, ge=1, le=10)


class VapiVoiceSettings(BaseModel):
    provider: str = "11labs"
    voice_id: str = "21m00Tcm4TlvDq8ikWAM"
    model: str = "eleven_turbo_v2_5"


class VapiTranscriberSettings(BaseModel):
    provider: str = "deepgram"
    model: str = "nova-3"
    language: str = "en-IN"
    endpointing: int = 400
    keywords: List[str] = Field(default_factory=list)


class VapiTurnTakingSettings(BaseModel):
    base_wait_seconds: float = 0.7
    smart_endpointing_type: str = "sigmoid"
    barge_in_words: int = 1
    barge_in_voice_duration: float = 0.4
    barge_in_backoff_seconds: float = 1.0


class VapiAssistantPayload(BaseModel):
    name: str
    model: dict
    voice: dict
    transcriber: dict
    start_speaking_plan: dict
    stop_speaking_plan: dict
    first_message: str


class InterviewSessionState(BaseModel):
    session_id: str
    role: str
    level: str
    tech_stack: List[str]
    interview_type: str
    questions: List[str]
    current_index: int = 0
    status: str = "active"
    vapi_assistant_id: Optional[str] = None
