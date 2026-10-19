"""
tests/test_interview_module.py — Comprehensive tests for Module 1 (Question Generation) and Module 2 (Voice Interviewer & Turn-Taking).
"""

import pytest
import re
from fastapi.testclient import TestClient

from dashboard.server import DashboardServer
from interview.models import QuestionGenerationRequest, AdvancedQuestionRequest
from interview.question_service import QuestionGenerationService, _clean_special_characters
from interview.voice_service import VoiceInterviewerService
from interview.config import (
    GROQ_MODEL,
    GROQ_TEMPERATURE,
    DEEPGRAM_MODEL,
    DEEPGRAM_LANGUAGE,
    DEEPGRAM_ENDPOINTING_MS,
    BASE_WAIT_SECONDS,
    SMART_ENDPOINTING_TYPE,
    BARGE_IN_WORDS,
    BARGE_IN_VOICE_DURATION,
    BARGE_IN_BACKOFF_SECONDS
)


def has_forbidden_special_chars(text: str) -> bool:
    """Checks if any forbidden special character exists in the text."""
    # Markdown symbols, backticks, asterisks, hashtags, smart quotes, bullet chars
    forbidden_pattern = re.compile(r'[*_`#~<>\[\]{}\\^|“”"]')
    return bool(forbidden_pattern.search(text))


# ── Module 1 Tests ────────────────────────────────────────────────────────────

def test_clean_special_characters():
    dirty_samples = [
        "**1. What are the trade-offs of microservices vs monoliths?**",
        "## Question 2: How do you handle `distributed locking` in Redis?",
        "* Can you explain *eventual consistency* in Kafka?",
        "3. Explain “ACID” properties in PostgreSQL?",
    ]
    for sample in dirty_samples:
        cleaned = _clean_special_characters(sample)
        assert not has_forbidden_special_chars(cleaned), f"Failed cleaning: {cleaned}"
        assert not re.match(r'^(?:\d+[\s:.-]+|Question\s*\d+)', cleaned), f"Numbering not stripped: {cleaned}"
        assert cleaned.endswith("?"), f"Should end with question mark: {cleaned}"


def test_question_generation_service():
    service = QuestionGenerationService()
    req = QuestionGenerationRequest(
        role="Senior Backend Engineer",
        level="Senior",
        tech_stack=["Python", "FastAPI", "PostgreSQL", "Docker", "Redis"],
        interview_type="System Design",
        question_count=4
    )
    result = service.generate_questions(req)
    assert "questions" in result
    assert len(result["questions"]) == 4
    for q in result["questions"]:
        assert isinstance(q, str) and len(q) > 10
        assert not has_forbidden_special_chars(q), f"Question contains forbidden special characters: {q}"
        assert not re.match(r'^\d+[\s:.-]+', q), f"Question has bullet/number prefix: {q}"
    assert result["interview_id"].startswith("interview_")


def test_advanced_question_generation_service():
    service = QuestionGenerationService()
    prev = [
        "How do you design an idempotency key mechanism for payment processing?",
        "What are the trade-offs between optimistic and pessimistic locking?"
    ]
    req = AdvancedQuestionRequest(
        role="Distributed Systems Architect",
        level="Staff",
        tech_stack=["Go", "Kafka", "Raft", "Kubernetes"],
        previous_questions=prev,
        question_count=3
    )
    result = service.generate_advanced_questions(req)
    assert "questions" in result
    assert len(result["questions"]) == 3
    for q in result["questions"]:
        assert isinstance(q, str)
        assert not has_forbidden_special_chars(q), f"Advanced question has special characters: {q}"
        assert not re.match(r'^\d+[\s:.-]+', q), f"Question has bullet/number prefix: {q}"


# ── Module 2 Tests ────────────────────────────────────────────────────────────

def test_voice_interviewer_deepgram_nova3_config():
    service = VoiceInterviewerService()
    transcriber = service.build_transcriber_config(["Python", "Kubernetes", "Redis"])
    
    assert transcriber["provider"] == "deepgram"
    assert transcriber["model"] == "nova-3"
    assert transcriber["language"] == "en-IN"
    assert transcriber["endpointing"] == 400
    assert "Kubernetes:2" in transcriber["keywords"]
    assert "Redis:2" in transcriber["keywords"]


def test_voice_interviewer_turn_taking_and_barge_in():
    service = VoiceInterviewerService()
    plans = service.build_turn_taking_plans()

    start_plan = plans["startSpeakingPlan"]
    stop_plan = plans["stopSpeakingPlan"]

    # 0.7 s base wait plus sigmoid smart-endpointing
    assert start_plan["waitSeconds"] == 0.7
    assert start_plan["smartEndpointingPlan"]["type"] == "sigmoid"

    # barge-in needs one word, 0.4 s voice, 1.0 s back-off
    assert stop_plan["numWords"] == 1
    assert stop_plan["voiceDuration"] == 0.4
    assert stop_plan["backoffSeconds"] == 1.0


def test_voice_interviewer_payload_assembly():
    service = VoiceInterviewerService()
    payload = service.build_vapi_assistant_payload(
        role="Full Stack Engineer",
        level="Senior",
        questions=["How do you profile memory leaks in Node.js?", "What is your strategy for database connection pooling?"],
        tech_stack=["Node.js", "React", "PostgreSQL"]
    )
    assert payload["voice"]["provider"] == "11labs"
    assert payload["transcriber"]["model"] == "nova-3"
    assert payload["transcriber"]["language"] == "en-IN"
    assert payload["startSpeakingPlan"]["waitSeconds"] == 0.7
    assert payload["startSpeakingPlan"]["smartEndpointingPlan"]["type"] == "sigmoid"
    assert payload["stopSpeakingPlan"]["numWords"] == 1
    assert payload["stopSpeakingPlan"]["voiceDuration"] == 0.4
    assert payload["stopSpeakingPlan"]["backoffSeconds"] == 1.0


# ── FastAPI Endpoints Integration Tests ───────────────────────────────────────

@pytest.fixture
def client():
    server = DashboardServer()
    return TestClient(server.app)


def test_api_generate_questions(client):
    payload = {
        "role": "Machine Learning Engineer",
        "level": "Senior",
        "tech_stack": ["PyTorch", "CUDA", "FastAPI", "Triton"],
        "interview_type": "Technical Deep Dive",
        "question_count": 3
    }
    resp = client.post("/api/interview/generate-questions", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["questions"]) == 3
    for q in data["questions"]:
        assert not has_forbidden_special_chars(q)


def test_api_advanced_questions(client):
    payload = {
        "role": "Cloud Architect",
        "level": "Staff",
        "tech_stack": "AWS, Terraform, Kubernetes",
        "previous_questions": ["How do you structure VPC peering vs Transit Gateway?"],
        "question_count": 2
    }
    resp = client.post("/api/interview/advanced-questions", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["questions"]) == 2
    for q in data["questions"]:
        assert not has_forbidden_special_chars(q)


def test_api_voice_config(client):
    resp = client.get("/api/interview/voice-config?tech_stack=FastAPI,Docker")
    assert resp.status_code == 200
    data = resp.json()
    assert data["transcriber"]["model"] == "nova-3"
    assert data["transcriber"]["language"] == "en-IN"
    assert data["transcriber"]["endpointing"] == 400
    assert data["turn_taking"]["startSpeakingPlan"]["waitSeconds"] == 0.7
    assert data["turn_taking"]["startSpeakingPlan"]["smartEndpointingPlan"]["type"] == "sigmoid"
    assert data["turn_taking"]["stopSpeakingPlan"]["numWords"] == 1
    assert data["turn_taking"]["stopSpeakingPlan"]["voiceDuration"] == 0.4
    assert data["turn_taking"]["stopSpeakingPlan"]["backoffSeconds"] == 1.0


def test_api_create_assistant(client):
    payload = {
        "role": "Backend Engineer",
        "level": "Mid-Level",
        "questions": ["How do you handle race conditions in database transactions?"],
        "tech_stack": ["Go", "PostgreSQL"]
    }
    resp = client.post("/api/interview/create-assistant", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert "assistant" in data
    assert data["assistant"]["transcriber"]["model"] == "nova-3"
    assert data["assistant"]["voice"]["provider"] == "11labs"


def test_api_turn_interaction_vague_answer(client):
    payload = {
        "role": "Senior Engineer",
        "level": "Senior",
        "current_question": "How would you optimize high write load on your relational database?",
        "candidate_answer": "I would just use a cache maybe."
    }
    resp = client.post("/api/interview/turn-interaction", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["is_vague"] is True
    assert data["status"] == "probe_followup"
    assert "trade-offs" in data["spoken_reply"] or "deeper" in data["spoken_reply"]


def test_api_turn_interaction_solid_answer(client):
    payload = {
        "role": "Senior Engineer",
        "level": "Senior",
        "current_question": "How would you optimize high write load on your relational database?",
        "candidate_answer": "We can implement write buffering using Kafka, batch inserts via worker pools, partition the tables by range or hash, and tune WAL flush sync."
    }
    resp = client.post("/api/interview/turn-interaction", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["is_vague"] is False
    assert data["status"] == "progress"
