"""
intel/youtube_learning_models.py — Data models for JARVIS YouTube AI Learning System.
"""

from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import Any, Optional
import datetime


def utc_now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


@dataclass
class VideoMetadata:
    video_id: str
    url: str
    title: str = ""
    author: str = ""
    author_url: str = ""
    thumbnail_url: str = ""
    duration_seconds: float = 0.0
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> VideoMetadata:
        return cls(
            video_id=data.get("video_id", ""),
            url=data.get("url", ""),
            title=data.get("title", ""),
            author=data.get("author", ""),
            author_url=data.get("author_url", ""),
            thumbnail_url=data.get("thumbnail_url", ""),
            duration_seconds=float(data.get("duration_seconds", 0.0)),
            description=data.get("description", ""),
        )


@dataclass
class TranscriptSnippet:
    text: str
    start: float
    duration: float = 0.0
    time_str: str = "00:00"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TranscriptSnippet:
        return cls(
            text=data.get("text", ""),
            start=float(data.get("start", 0.0)),
            duration=float(data.get("duration", 0.0)),
            time_str=data.get("time_str", "00:00"),
        )


@dataclass
class TopicBreakdown:
    title: str
    time_str: str
    seconds: float
    summary: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TopicBreakdown:
        return cls(
            title=data.get("title", ""),
            time_str=data.get("time_str", "00:00"),
            seconds=float(data.get("seconds", 0.0)),
            summary=data.get("summary", ""),
        )


@dataclass
class QuizQuestion:
    question: str
    options: list[str]
    answer_index: int
    explanation: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> QuizQuestion:
        return cls(
            question=data.get("question", ""),
            options=data.get("options", []),
            answer_index=int(data.get("answer_index", 0)),
            explanation=data.get("explanation", ""),
        )


@dataclass
class Flashcard:
    front: str
    back: str
    topic: str = "General"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Flashcard:
        return cls(
            front=data.get("front", ""),
            back=data.get("back", ""),
            topic=data.get("topic", "General"),
        )


@dataclass
class QATurn:
    id: str
    question: str
    answer: str
    video_facts: str = ""
    jarvis_extension: str = ""
    timestamp_references: list[str] = field(default_factory=list)
    created_at: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> QATurn:
        return cls(
            id=data.get("id", ""),
            question=data.get("question", ""),
            answer=data.get("answer", ""),
            video_facts=data.get("video_facts", ""),
            jarvis_extension=data.get("jarvis_extension", ""),
            timestamp_references=data.get("timestamp_references", []),
            created_at=data.get("created_at", utc_now_iso()),
        )


@dataclass
class YouTubeSession:
    id: str
    video_id: str
    video_url: str
    title: str = ""
    author: str = ""
    thumbnail_url: str = ""
    language: str = "English"  # 'English' | 'Tamil' | 'Tanglish' | 'Auto'
    level: str = "Intermediate"  # 'Beginner' | 'Intermediate' | 'Advanced'
    style: str = "Step-by-step"  # 'Simple explanation' | 'Step-by-step' | 'Practical examples' | 'Technical deep dive'
    has_transcript: bool = True
    transcript_snippets: list[TranscriptSnippet] = field(default_factory=list)
    full_transcript: str = ""
    topics: list[TopicBreakdown] = field(default_factory=list)
    summary: str = ""
    detailed_explanation: str = ""
    key_takeaways: list[str] = field(default_factory=list)
    quiz: list[QuizQuestion] = field(default_factory=list)
    flashcards: list[Flashcard] = field(default_factory=list)
    notes_markdown: str = ""
    qa_turns: list[QATurn] = field(default_factory=list)
    created_at: str = field(default_factory=utc_now_iso)
    updated_at: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "video_id": self.video_id,
            "video_url": self.video_url,
            "title": self.title,
            "author": self.author,
            "thumbnail_url": self.thumbnail_url,
            "language": self.language,
            "level": self.level,
            "style": self.style,
            "has_transcript": self.has_transcript,
            "transcript_snippets": [s.to_dict() for s in self.transcript_snippets],
            "full_transcript": self.full_transcript,
            "topics": [t.to_dict() for t in self.topics],
            "summary": self.summary,
            "detailed_explanation": self.detailed_explanation,
            "key_takeaways": self.key_takeaways,
            "quiz": [q.to_dict() for q in self.quiz],
            "flashcards": [f.to_dict() for f in self.flashcards],
            "notes_markdown": self.notes_markdown,
            "qa_turns": [qa.to_dict() for qa in self.qa_turns],
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> YouTubeSession:
        return cls(
            id=data.get("id", ""),
            video_id=data.get("video_id", ""),
            video_url=data.get("video_url", ""),
            title=data.get("title", ""),
            author=data.get("author", ""),
            thumbnail_url=data.get("thumbnail_url", ""),
            language=data.get("language", "English"),
            level=data.get("level", "Intermediate"),
            style=data.get("style", "Step-by-step"),
            has_transcript=bool(data.get("has_transcript", True)),
            transcript_snippets=[TranscriptSnippet.from_dict(s) for s in data.get("transcript_snippets", [])],
            full_transcript=data.get("full_transcript", ""),
            topics=[TopicBreakdown.from_dict(t) for t in data.get("topics", [])],
            summary=data.get("summary", ""),
            detailed_explanation=data.get("detailed_explanation", ""),
            key_takeaways=data.get("key_takeaways", []),
            quiz=[QuizQuestion.from_dict(q) for q in data.get("quiz", [])],
            flashcards=[Flashcard.from_dict(f) for f in data.get("flashcards", [])],
            notes_markdown=data.get("notes_markdown", ""),
            qa_turns=[QATurn.from_dict(qa) for qa in data.get("qa_turns", [])],
            created_at=data.get("created_at", utc_now_iso()),
            updated_at=data.get("updated_at", utc_now_iso()),
        )
