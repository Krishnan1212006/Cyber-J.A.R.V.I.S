"""
tests/test_youtube_learning.py — Unit tests for YouTube AI Learning subsystem.

Validates:
- URL parsing & ID extraction across multiple YouTube formats
- Transcript parsing (timestamped lines, user fallback notes)
- Multi-language prompt construction (Tamil, Tanglish, English)
- Personalized explanation generation & grounded fact vs expansion separation
- Artifact generation (Quiz, Flashcards, Study Notes, PDF, PPTX)
- Grounded Q&A against video transcript
- SQLite persistence (save, list, search, filter, delete)
- FastAPI REST endpoints
"""

import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from intel.llm_provider import MockLLMProvider
from intel.youtube_learning_models import (
    Flashcard,
    QATurn,
    QuizQuestion,
    TopicBreakdown,
    TranscriptSnippet,
    VideoMetadata,
    YouTubeSession,
)
from intel.youtube_learning_service import (
    GroundedQAService,
    LearningArtifactService,
    PersonalizedTeachingService,
    TranscriptService,
    YouTubeLearningService,
    _seconds_to_time_str,
    _time_str_to_seconds,
)


class TestYouTubeModelsAndHelpers(unittest.TestCase):
    def test_time_conversions(self):
        self.assertEqual(_seconds_to_time_str(0), "00:00")
        self.assertEqual(_seconds_to_time_str(65), "01:05")
        self.assertEqual(_seconds_to_time_str(3665), "01:01:05")

        self.assertEqual(_time_str_to_seconds("00:00"), 0.0)
        self.assertEqual(_time_str_to_seconds("01:05"), 65.0)
        self.assertEqual(_time_str_to_seconds("01:01:05"), 3665.0)

    def test_youtube_session_serialization(self):
        meta = VideoMetadata(
            video_id="abc12345678",
            url="https://www.youtube.com/watch?v=abc12345678",
            title="Introduction to Machine Learning",
            author="AI Academy",
        )
        session = YouTubeSession(
            id="test-session-1",
            video_id=meta.video_id,
            video_url=meta.url,
            title=meta.title,
            author=meta.author,
            language="Tamil",
            level="Beginner",
            style="Simple explanation",
            topics=[
                TopicBreakdown(title="Intro", time_str="00:00", seconds=0.0, summary="Basics")
            ],
            summary="A comprehensive beginner guide to machine learning.",
            detailed_explanation="# Overview\n\n### [Video Facts]\n- Covers linear regression\n\n### [JARVIS Expansion]\n- Try implementing with NumPy",
            key_takeaways=["Understand loss function", "Optimize weights"],
            quiz=[
                QuizQuestion(
                    question="What is loss?",
                    options=["Cost error", "Benefit", "Speed", "None"],
                    answer_index=0,
                    explanation="Loss measures prediction error.",
                )
            ],
            flashcards=[
                Flashcard(front="Gradient Descent", back="Optimization algorithm", topic="Math")
            ],
        )

        d = session.to_dict()
        self.assertEqual(d["id"], "test-session-1")
        self.assertEqual(d["language"], "Tamil")
        self.assertEqual(len(d["topics"]), 1)
        self.assertEqual(len(d["quiz"]), 1)
        self.assertEqual(len(d["flashcards"]), 1)

        restored = YouTubeSession.from_dict(d)
        self.assertEqual(restored.id, session.id)
        self.assertEqual(restored.title, session.title)
        self.assertEqual(restored.language, "Tamil")
        self.assertEqual(len(restored.topics), 1)
        self.assertEqual(restored.topics[0].title, "Intro")


class TestTranscriptService(unittest.TestCase):
    def test_url_extraction(self):
        urls = [
            ("https://www.youtube.com/watch?v=dQw4w9WgXcQ", "dQw4w9WgXcQ"),
            ("https://youtube.com/watch?v=dQw4w9WgXcQ&t=120", "dQw4w9WgXcQ"),
            ("https://youtu.be/dQw4w9WgXcQ", "dQw4w9WgXcQ"),
            ("https://www.youtube.com/embed/dQw4w9WgXcQ", "dQw4w9WgXcQ"),
            ("https://www.youtube.com/shorts/dQw4w9WgXcQ", "dQw4w9WgXcQ"),
            ("https://m.youtube.com/watch?v=dQw4w9WgXcQ", "dQw4w9WgXcQ"),
            ("dQw4w9WgXcQ", "dQw4w9WgXcQ"),
        ]
        for url, expected_id in urls:
            self.assertEqual(TranscriptService.extract_video_id(url), expected_id)

        self.assertIsNone(TranscriptService.extract_video_id("https://vimeo.com/123456"))
        self.assertIsNone(TranscriptService.extract_video_id(""))

    def test_parse_user_provided_transcript_with_timestamps(self):
        raw = """0:00 Welcome to cybersecurity basics.
0:30 Today we discuss SQL Injection attacks.
1:15 Parameterized queries prevent these vulnerabilities.
2:00 In summary, never concatenate raw user input."""

        snippets, full_text = TranscriptService.parse_user_provided_transcript(raw)
        self.assertEqual(len(snippets), 4)
        self.assertEqual(snippets[0].time_str, "00:00")
        self.assertEqual(snippets[1].time_str, "00:30")
        self.assertEqual(snippets[2].time_str, "01:15")
        self.assertEqual(snippets[3].time_str, "02:00")
        self.assertIn("cybersecurity basics", full_text)
        self.assertIn("Parameterized queries", full_text)

    def test_parse_user_provided_transcript_plain_text(self):
        raw = "This is a paragraph without timestamps.\nHere is another key takeaway from the speaker."
        snippets, full_text = TranscriptService.parse_user_provided_transcript(raw)
        self.assertEqual(len(snippets), 2)
        self.assertIn("paragraph without timestamps", full_text)


class TestPersonalizedTeachingService(unittest.TestCase):
    def test_build_prompt_languages(self):
        snippets = [TranscriptSnippet(text="Hello", start=0.0, time_str="00:00")]

        # Test Tamil
        prompt_tamil = PersonalizedTeachingService.build_analysis_prompt(
            title="FastAPI Guide",
            transcript="FastAPI is modern.",
            language="Tamil",
            level="Beginner",
            style="Step-by-step",
            snippets=snippets,
        )
        self.assertIn("Tamil", prompt_tamil)
        self.assertIn("தமிழ்", prompt_tamil)

        # Test Tanglish
        prompt_tanglish = PersonalizedTeachingService.build_analysis_prompt(
            title="FastAPI Guide",
            transcript="FastAPI is modern.",
            language="Tanglish",
            level="Intermediate",
            style="Practical examples",
            snippets=snippets,
        )
        self.assertIn("Tanglish", prompt_tanglish)

        # Test Grounding rules
        self.assertIn("[Video Facts]", prompt_tanglish)
        self.assertIn("[JARVIS Expansion]", prompt_tanglish)

    def test_analyze_video_mock(self):
        mock_llm = MockLLMProvider()
        snippets = [
            TranscriptSnippet(text="Intro to Cryptography", start=0.0, time_str="00:00"),
            TranscriptSnippet(text="Public key RSA", start=60.0, time_str="01:00"),
        ]
        summary, topics, explanation, takeaways = PersonalizedTeachingService.analyze_video(
            title="Cryptography 101",
            transcript="Intro to Cryptography. Public key RSA.",
            language="English",
            level="Intermediate",
            style="Step-by-step",
            snippets=snippets,
            llm=mock_llm,
        )
        self.assertTrue(len(summary) > 0)
        self.assertTrue(len(topics) >= 1)
        self.assertTrue(len(explanation) > 0)
        self.assertTrue(len(takeaways) >= 1)


class TestLearningArtifactService(unittest.TestCase):
    def setUp(self):
        self.session = YouTubeSession(
            id="sess-art-1",
            video_id="dQw4w9WgXcQ",
            video_url="https://www.youtube.com/watch?v=dQw4w9WgXcQ",
            title="Network Security Architecture",
            author="Cyber Academy",
            language="English",
            level="Intermediate",
            style="Technical deep dive",
            summary="Covers firewalls, zero-trust architectures, and packet inspection.",
            topics=[
                TopicBreakdown(title="Firewalls", time_str="00:00", seconds=0.0, summary="Packet filtering"),
                TopicBreakdown(title="Zero Trust", time_str="02:30", seconds=150.0, summary="Identity perimeter"),
            ],
            detailed_explanation="# Lesson Notes\n\n### [Video Facts]\n- Explains SPI firewalls\n\n### [JARVIS Expansion]\n- Configure egress filtering",
            key_takeaways=["Enforce least privilege", "Inspect encrypted traffic"],
            quiz=[
                QuizQuestion(
                    question="What is the core premise of Zero Trust?",
                    options=["Never trust, always verify", "Trust all internal network traffic", "Rely solely on perimeter firewalls", "Disable logging"],
                    answer_index=0,
                    explanation="Zero Trust assumes breach and validates continuously.",
                )
            ],
            flashcards=[
                Flashcard(front="Zero Trust", back="Never trust, always verify", topic="Architecture")
            ],
        )

    def test_notes_markdown_generation(self):
        notes = LearningArtifactService.generate_notes_markdown(self.session)
        self.assertIn("Network Security Architecture", notes)
        self.assertIn("Executive Summary", notes)
        self.assertIn("Video Topics & Timestamps", notes)
        self.assertIn("Key Takeaways", notes)

    def test_export_pdf(self):
        pdf_bytes = LearningArtifactService.export_pdf(self.session)
        self.assertIsInstance(pdf_bytes, bytes)
        self.assertTrue(len(pdf_bytes) > 500)
        # PDF magic header %PDF
        self.assertTrue(pdf_bytes.startswith(b"%PDF"))

    def test_export_pptx(self):
        pptx_bytes = LearningArtifactService.export_pptx(self.session)
        self.assertIsInstance(pptx_bytes, bytes)
        self.assertTrue(len(pptx_bytes) > 1000)
        # Zip/Office Open XML magic header PK\x03\x04
        self.assertTrue(pptx_bytes.startswith(b"PK\x03\x04"))


class TestGroundedQAService(unittest.TestCase):
    def test_grounded_qa(self):
        session = YouTubeSession(
            id="sess-qa-1",
            video_id="test1234567",
            video_url="https://youtube.com/watch?v=test1234567",
            title="FastAPI Crash Course",
            full_transcript="In this video we build a FastAPI application. We use Pydantic models for validation and Uvicorn as our ASGI server.",
            transcript_snippets=[
                TranscriptSnippet(text="FastAPI application", start=10.0, time_str="00:10"),
                TranscriptSnippet(text="Pydantic models for validation", start=45.0, time_str="00:45"),
                TranscriptSnippet(text="Uvicorn ASGI server", start=90.0, time_str="01:30"),
            ],
        )
        mock_llm = MockLLMProvider()
        turn = GroundedQAService.answer_question(
            session=session,
            question="What library is used for request validation?",
            llm=mock_llm,
        )
        self.assertIsInstance(turn, QATurn)
        self.assertEqual(turn.question, "What library is used for request validation?")
        self.assertTrue(len(turn.answer) > 0)
        # Timestamp references matched from snippets
        self.assertIn("00:45", turn.timestamp_references)


class TestYouTubeLearningServicePersistence(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_yt.db"
        self.service = YouTubeLearningService(db_path=self.db_path)

    def tearDown(self):
        self.service.close()
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    def test_crud_lifecycle(self):
        # 1. Create session via analyze
        session, notice = self.service.analyze_and_create_session(
            url="https://www.youtube.com/watch?v=dQw4w9WgXcQ",
            language="English",
            level="Intermediate",
            style="Step-by-step",
            user_transcript="0:00 Welcome to this lesson.\n0:30 Core concept explained.",
            llm=MockLLMProvider(),
        )
        self.assertIsNotNone(session.id)
        self.assertEqual(session.video_id, "dQw4w9WgXcQ")
        self.assertEqual(len(session.topics), 2)

        # 2. Retrieve session
        retrieved = self.service.get_session(session.id)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.id, session.id)
        self.assertEqual(retrieved.language, "English")

        # 3. List sessions
        sessions = self.service.list_sessions()
        self.assertEqual(len(sessions), 1)
        self.assertEqual(sessions[0]["id"], session.id)

        # 4. Search sessions
        matched = self.service.list_sessions(search=session.title[:6])
        self.assertEqual(len(matched), 1)
        unmatched = self.service.list_sessions(search="nonexistentxyz123456")
        self.assertEqual(len(unmatched), 0)

        # 5. Ask question
        turn = self.service.ask_question(
            session_id=session.id,
            question="What is the core concept?",
            llm=MockLLMProvider(),
        )
        self.assertIsNotNone(turn.id)
        updated = self.service.get_session(session.id)
        self.assertEqual(len(updated.qa_turns), 1)

        # 6. Delete session
        deleted = self.service.delete_session(session.id)
        self.assertTrue(deleted)
        self.assertIsNone(self.service.get_session(session.id))
        self.assertEqual(len(self.service.list_sessions()), 0)


class TestYouTubeLearningAPI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            from fastapi.testclient import TestClient
            from intel.youtube_learning_api import router, set_service
            from fastapi import FastAPI

            app = FastAPI()
            app.include_router(router)
            cls.client = TestClient(app)
            cls.api_available = True

            cls.temp_dir = tempfile.TemporaryDirectory()
            cls.test_db = Path(cls.temp_dir.name) / "api_test.db"
            cls.test_svc = YouTubeLearningService(db_path=cls.test_db)
            set_service(cls.test_svc)
        except ImportError:
            cls.api_available = False

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "test_svc"):
            cls.test_svc.close()
        if hasattr(cls, "temp_dir"):
            try:
                cls.temp_dir.cleanup()
            except Exception:
                pass

    @patch("intel.youtube_learning_service.get_llm_provider", return_value=MockLLMProvider())
    def test_api_endpoints(self, mock_llm_getter):
        if not self.api_available:
            self.skipTest("FastAPI TestClient not available")

        # 1. Analyze video
        res = self.client.post(
            "/api/youtube-learning/analyze",
            json={
                "url": "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
                "language": "Tanglish",
                "level": "Beginner",
                "style": "Simple explanation",
                "transcript": "0:00 Welcome to network fundamentals.\n0:45 IP addressing.",
            },
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data["ok"])
        session_id = data["session"]["id"]
        self.assertEqual(data["session"]["language"], "Tanglish")

        # 2. List sessions
        list_res = self.client.get("/api/youtube-learning/sessions")
        self.assertEqual(list_res.status_code, 200)
        self.assertGreaterEqual(list_res.json()["total"], 1)

        # 3. Get session
        get_res = self.client.get(f"/api/youtube-learning/sessions/{session_id}")
        self.assertEqual(get_res.status_code, 200)
        self.assertEqual(get_res.json()["session"]["id"], session_id)

        # 4. Ask grounded question
        qa_res = self.client.post(
            f"/api/youtube-learning/sessions/{session_id}/ask",
            json={"question": "What is covered in IP addressing?"},
        )
        self.assertEqual(qa_res.status_code, 200)
        self.assertTrue(qa_res.json()["ok"])

        # 5. Regenerate artifacts
        art_res = self.client.post(
            f"/api/youtube-learning/sessions/{session_id}/artifacts",
            json={"artifact_type": "quiz"},
        )
        self.assertEqual(art_res.status_code, 200)

        # 6. Export as markdown
        exp_md = self.client.get(f"/api/youtube-learning/sessions/{session_id}/export?format=markdown")
        self.assertEqual(exp_md.status_code, 200)
        self.assertIn("text/markdown", exp_md.headers["content-type"])

        # 7. Export as PDF
        exp_pdf = self.client.get(f"/api/youtube-learning/sessions/{session_id}/export?format=pdf")
        self.assertEqual(exp_pdf.status_code, 200)
        self.assertEqual(exp_pdf.headers["content-type"], "application/pdf")
        self.assertTrue(exp_pdf.content.startswith(b"%PDF"))

        # 8. Export as PPTX
        exp_pptx = self.client.get(f"/api/youtube-learning/sessions/{session_id}/export?format=pptx")
        self.assertEqual(exp_pptx.status_code, 200)
        self.assertTrue(exp_pptx.content.startswith(b"PK\x03\x04"))

        # 9. Delete session
        del_res = self.client.delete(f"/api/youtube-learning/sessions/{session_id}")
        self.assertEqual(del_res.status_code, 200)
        self.assertTrue(del_res.json()["ok"])


if __name__ == "__main__":
    unittest.main()
