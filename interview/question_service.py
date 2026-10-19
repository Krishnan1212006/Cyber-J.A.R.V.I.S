"""
interview/question_service.py — Module 1: AI Question Generation & Regeneration.

Uses gpt-oss-120b on Groq at temperature 1.0 to generate and regenerate interview questions.
Ensures output is a clean JSON array of strings with no special characters.
"""

import json
import re
import uuid
from typing import List, Union
from interview.config import GROQ_API_KEY, GROQ_MODEL, GROQ_FALLBACK_MODEL, GROQ_TEMPERATURE
from interview.models import QuestionGenerationRequest, AdvancedQuestionRequest


def _clean_special_characters(text: str) -> str:
    """
    Remove all special characters (markdown symbols, backticks, asterisks, hash signs,
    bullet points, excessive quotes, non-alphanumeric punctuation) leaving only clean
    plain English question text with standard sentence punctuation (. , ?).
    """
    # Remove markdown formatting (*, _, `, #, ~, <, >, [, ], {, }, \, |, ^)
    text = re.sub(r'[*_`#~<>\[\]{}\\^|]', '', text)
    # Remove smart/curled quotes
    text = text.replace('“', '').replace('”', '').replace('"', '').replace("'", "")
    # Remove leading numbering like "1. ", "Question 1: ", etc.
    text = re.sub(r'^(?:Question\s*\d+[\s:.-]*|\d+[\s:.-]+)', '', text.strip())
    # Normalize whitespace
    text = re.sub(r'\s+', ' ', text).strip()
    # Ensure it ends with a question mark
    if text and not text.endswith('?'):
        text += '?'
    return text


def _parse_and_sanitize_questions(raw_output: str, expected_count: int) -> List[str]:
    """Parse JSON array from raw model text and sanitize every question."""
    questions = []
    
    # Try finding JSON array block
    match = re.search(r'\[[\s\S]*?\]', raw_output)
    if match:
        try:
            parsed = json.loads(match.group(0))
            if isinstance(parsed, list):
                for item in parsed:
                    if isinstance(item, str) and item.strip():
                        cleaned = _clean_special_characters(item)
                        if cleaned:
                            questions.append(cleaned)
                    elif isinstance(item, dict):
                        # Handle if model returned objects like {"question": "..."}
                        val = item.get("question") or item.get("text") or list(item.values())[0]
                        if isinstance(val, str):
                            cleaned = _clean_special_characters(val)
                            if cleaned:
                                questions.append(cleaned)
        except Exception:
            pass

    # Fallback line-by-line parsing if JSON structure was malformed
    if not questions:
        for line in raw_output.split('\n'):
            line = line.strip()
            if not line:
                continue
            if line.startswith(('[', ']', '{', '}')):
                continue
            cleaned = _clean_special_characters(line)
            if cleaned and len(cleaned) > 15:
                questions.append(cleaned)

    return questions[:expected_count]


class QuestionGenerationService:

    def __init__(self, api_key: str = GROQ_API_KEY):
        self.api_key = api_key or GROQ_API_KEY
        self.sessions = {}  # session_id -> {role, level, tech_stack, questions}

    def _get_groq_client(self):
        if not self.api_key:
            return None
        try:
            from groq import Groq
            return Groq(api_key=self.api_key)
        except Exception as e:
            print(f"[Groq] Client initialization failed: {e}")
            return None

    def generate_questions(self, req: QuestionGenerationRequest) -> dict:
        """
        Receives role, level, tech stack, interview type, and question count.
        Calls gpt-oss-120b on Groq at temperature 1.0.
        Returns a JSON array of questions with no special characters.
        """
        tech_list = req.tech_stack if isinstance(req.tech_stack, list) else [t.strip() for t in req.tech_stack.split(",") if t.strip()]
        tech_str = ", ".join(tech_list)

        prompt = (
            f"You are an expert technical interviewer hiring for a {req.level} {req.role}.\n"
            f"The candidate is being interviewed on: {tech_str}.\n"
            f"Interview Category: {req.interview_type}.\n\n"
            f"Generate exactly {req.question_count} high-quality, practical interview questions tailored to a {req.level} candidate.\n"
            f"RULES:\n"
            f"1. Return ONLY a valid JSON array of strings containing the questions.\n"
            f"2. Do NOT use any special characters like backticks, asterisks, hashtags, smart quotes, or bullet points.\n"
            f"3. Do NOT include numbers or prefixes in the questions.\n"
            f"4. Do NOT output any markdown, explanations, or conversational filler before or after the JSON array.\n"
            f"Example format: [\"What are the trade-offs of using connection pooling in high throughput systems?\", \"How do you handle schema migrations without service downtime?\"]"
        )

        client = self._get_groq_client()
        raw_text = ""
        model_used = GROQ_MODEL

        if client:
            try:
                # Primary attempt: gpt-oss-120b on Groq at temperature 1.0
                resp = client.chat.completions.create(
                    model=GROQ_MODEL,
                    messages=[
                        {"role": "system", "content": "You are an automated interview question generator. Output only a valid JSON array of strings with no special characters."},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=GROQ_TEMPERATURE,
                )
                raw_text = resp.choices[0].message.content or ""
            except Exception as e:
                print(f"[Groq] {GROQ_MODEL} call failed: {e}. Attempting fallback model...")
                try:
                    # Fallback model attempt on Groq
                    resp = client.chat.completions.create(
                        model=GROQ_FALLBACK_MODEL,
                        messages=[
                            {"role": "system", "content": "You are an automated interview question generator. Output only a valid JSON array of strings with no special characters."},
                            {"role": "user", "content": prompt}
                        ],
                        temperature=GROQ_TEMPERATURE,
                    )
                    raw_text = resp.choices[0].message.content or ""
                    model_used = GROQ_FALLBACK_MODEL
                except Exception as fb_err:
                    print(f"[Groq] Fallback also failed: {fb_err}")

        # If Groq is not configured or failed, generate tailored realistic questions
        if not raw_text:
            model_used = f"{GROQ_MODEL} (Synthesized Fallback Engine)"
            raw_text = self._fallback_question_bank(req.role, req.level, tech_list, req.interview_type, req.question_count)

        questions = _parse_and_sanitize_questions(raw_text, req.question_count)

        interview_id = f"interview_{uuid.uuid4().hex[:10]}"
        self.sessions[interview_id] = {
            "role": req.role,
            "level": req.level,
            "tech_stack": tech_list,
            "interview_type": req.interview_type,
            "questions": questions,
        }

        return {
            "interview_id": interview_id,
            "role": req.role,
            "level": req.level,
            "tech_stack": tech_list,
            "interview_type": req.interview_type,
            "questions": questions,
            "model_used": model_used
        }

    def generate_advanced_questions(self, req: AdvancedQuestionRequest) -> dict:
        """
        Advanced-question endpoint regenerates harder questions for an existing interview.
        Focuses on deep architectural edge cases, distributed failures, concurrency bottlenecks,
        and production incident forensics without special characters.
        """
        tech_list = req.tech_stack if isinstance(req.tech_stack, list) else [t.strip() for t in req.tech_stack.split(",") if t.strip()]
        tech_str = ", ".join(tech_list)
        prev_str = "\n".join(f"- {q}" for q in req.previous_questions) if req.previous_questions else "None specified"

        prompt = (
            f"You are conducting an advanced technical round for a {req.level} {req.role}.\n"
            f"Tech Stack: {tech_str}.\n"
            f"Previous questions already asked:\n{prev_str}\n\n"
            f"The candidate successfully answered standard questions. Now regenerate {req.question_count} significantly HARDER, advanced-tier questions.\n"
            f"Focus on:\n"
            f"- Edge cases and subtle race conditions\n"
            f"- Distributed system partition tolerances and split-brain scenarios\n"
            f"- High-concurrency performance bottlenecks, garbage collection pauses, or database deadlocks\n"
            f"- Production failure recovery and zero-downtime architecture trade-offs\n\n"
            f"RULES:\n"
            f"1. Return ONLY a valid JSON array of strings containing the questions.\n"
            f"2. Do NOT use any special characters like backticks, asterisks, hashtags, or bullet points.\n"
            f"3. Do NOT include numbers or prefixes in the questions.\n"
            f"4. Do NOT output any markdown formatting before or after the JSON array."
        )

        client = self._get_groq_client()
        raw_text = ""
        model_used = GROQ_MODEL

        if client:
            try:
                resp = client.chat.completions.create(
                    model=GROQ_MODEL,
                    messages=[
                        {"role": "system", "content": "You are an advanced interview question regenerator. Output only a valid JSON array of harder questions without special characters."},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=GROQ_TEMPERATURE,
                )
                raw_text = resp.choices[0].message.content or ""
            except Exception as e:
                try:
                    resp = client.chat.completions.create(
                        model=GROQ_FALLBACK_MODEL,
                        messages=[
                            {"role": "system", "content": "You are an advanced interview question regenerator. Output only a valid JSON array of harder questions without special characters."},
                            {"role": "user", "content": prompt}
                        ],
                        temperature=GROQ_TEMPERATURE,
                    )
                    raw_text = resp.choices[0].message.content or ""
                    model_used = GROQ_FALLBACK_MODEL
                except Exception:
                    pass

        if not raw_text:
            model_used = f"{GROQ_MODEL} (Advanced Synthesized Engine)"
            raw_text = self._fallback_advanced_bank(req.role, req.level, tech_list, req.question_count)

        harder_questions = _parse_and_sanitize_questions(raw_text, req.question_count)

        if req.interview_id and req.interview_id in self.sessions:
            self.sessions[req.interview_id]["questions"].extend(harder_questions)

        return {
            "interview_id": req.interview_id or f"interview_{uuid.uuid4().hex[:10]}",
            "role": req.role,
            "level": req.level,
            "tech_stack": tech_list,
            "interview_type": "Advanced Technical Deep Dive",
            "questions": harder_questions,
            "harder_questions": harder_questions,
            "model_used": model_used
        }

    def _fallback_question_bank(self, role: str, level: str, tech_stack: List[str], interview_type: str, count: int) -> str:
        """Deterministic high-quality fallback questions matching specifications."""
        t1 = tech_stack[0] if tech_stack else "the primary framework"
        t2 = tech_stack[1] if len(tech_stack) > 1 else "the database layer"

        q_list = [
            f"How do you design a resilient architecture using {t1} when handling unpredictable traffic spikes?",
            f"Can you explain how you prevent connection pool exhaustion when scaling {t2} under heavy concurrent loads?",
            f"What specific caching invalidation strategy would you implement to ensure data consistency without introducing latency?",
            f"How do you approach database schema migrations in a production environment with zero customer downtime?",
            f"Could you walk me through your methodology for profiling memory consumption and identifying CPU bottlenecks in {t1}?",
            f"How do you structure asynchronous message queues to ensure idempotency and prevent duplicate message processing?",
            f"What trade-offs do you evaluate when deciding between pessimistic locking and optimistic locking in distributed transactions?",
            f"How would you isolate and diagnose an intermittent latency spike occurring exclusively on tail p99 requests?"
        ]
        return json.dumps(q_list[:count])

    def _fallback_advanced_bank(self, role: str, level: str, tech_stack: List[str], count: int) -> str:
        """Deterministic advanced/harder questions probing edge cases and distributed failures."""
        t1 = tech_stack[0] if tech_stack else "the backend engine"
        q_list = [
            f"How do you resolve a distributed deadlock when two microservices attempt concurrent two-phase commits across partitioned databases?",
            f"Under what conditions would a memory leak in {t1} escape standard garbage collection metrics and how would you isolate the heap segment?",
            f"How do you architect a consensus protocol to survive a network partition without sacrificing read availability?",
            f"What is your approach to handling database read replica replication lag during high-frequency writes without stale reads?",
            f"How would you remediate a cascading failure triggered by an upstream circuit breaker tripping during peak traffic?"
        ]
        return json.dumps(q_list[:count])


# Singleton service instance
question_service = QuestionGenerationService()
