"""
intel/youtube_learning_service.py — Core backend service for YouTube AI Learning.

Orchestrates URL validation, metadata retrieval, caption extraction (with graceful fallback),
personalized multi-language teaching (Tamil, Tanglish, English), grounded Q&A,
artifact generation (Quizzes, Flashcards, Notes, PDF, PPTX), and SQLite persistence.
"""

from __future__ import annotations

import io
import json
import logging
import os
import re
import sqlite3
import threading
import urllib.request
import uuid
from pathlib import Path
from typing import Any, Optional

from .llm_provider import BaseLLMProvider, get_llm_provider
from .youtube_learning_models import (
    Flashcard,
    QATurn,
    QuizQuestion,
    TopicBreakdown,
    TranscriptSnippet,
    VideoMetadata,
    YouTubeSession,
    utc_now_iso,
)

logger = logging.getLogger(__name__)


def _seconds_to_time_str(seconds: float) -> str:
    secs = int(seconds)
    m, s = divmod(secs, 60)
    h, m = divmod(m, 60)
    if h > 0:
        return f"{h:02d}:{m:02d}:{s:02d}"
    return f"{m:02d}:{s:02d}"


def _time_str_to_seconds(time_str: str) -> float:
    parts = time_str.strip().split(":")
    try:
        if len(parts) == 3:
            return float(parts[0]) * 3600 + float(parts[1]) * 60 + float(parts[2])
        if len(parts) == 2:
            return float(parts[0]) * 60 + float(parts[1])
        if len(parts) == 1:
            return float(parts[0])
    except Exception:
        pass
    return 0.0


# ── 1. TRANSCRIPT & METADATA SERVICE ──────────────────────────────────────────

class TranscriptService:
    """Handles YouTube URL extraction, oEmbed metadata retrieval, and transcript fetching."""

    YOUTUBE_REGEX = re.compile(
        r"(?:https?:\/\/)?(?:www\.|m\.)?(?:youtube\.com\/(?:watch\?.*?v=|embed\/|v\/|shorts\/)|youtu\.be\/)([a-zA-Z0-9_-]{11})"
    )

    @classmethod
    def extract_video_id(cls, url: str) -> Optional[str]:
        if not url:
            return None
        match = cls.YOUTUBE_REGEX.search(url.strip())
        if match:
            return match.group(1)
        # Check if the user passed raw 11-char ID directly
        cleaned = url.strip()
        if re.fullmatch(r"[a-zA-Z0-9_-]{11}", cleaned):
            return cleaned
        return None

    @classmethod
    def fetch_metadata(cls, video_id: str) -> VideoMetadata:
        url = f"https://www.youtube.com/watch?v={video_id}"
        meta = VideoMetadata(
            video_id=video_id,
            url=url,
            title=f"YouTube Video ({video_id})",
            thumbnail_url=f"https://img.youtube.com/vi/{video_id}/hqdefault.jpg",
        )
        try:
            oembed_url = f"https://www.youtube.com/oembed?url=https://www.youtube.com/watch?v={video_id}&format=json"
            req = urllib.request.Request(
                oembed_url,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) JARVIS/24"},
            )
            with urllib.request.urlopen(req, timeout=8) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                meta.title = data.get("title", meta.title)
                meta.author = data.get("author_name", "")
                meta.author_url = data.get("author_url", "")
                if data.get("thumbnail_url"):
                    meta.thumbnail_url = data.get("thumbnail_url")
        except Exception as e:
            logger.warning(f"oEmbed fetch for {video_id} failed: {e}")
        return meta

    @classmethod
    def fetch_transcript(
        cls, video_id: str, preferred_lang: str = "en"
    ) -> tuple[list[TranscriptSnippet], str, Optional[str]]:
        """
        Attempt to fetch captions via youtube_transcript_api.
        Returns: (snippets, full_text, error_message)
        """
        snippets: list[TranscriptSnippet] = []
        full_text = ""
        error_msg: Optional[str] = None

        try:
            from youtube_transcript_api import YouTubeTranscriptApi

            api = YouTubeTranscriptApi()

            # Map requested language
            lang_codes = ["en", "en-US", "en-GB"]
            if preferred_lang.lower() in ("tamil", "ta", "tanglish"):
                lang_codes = ["ta", "en", "en-US"]

            raw_snippets = None
            try:
                # Try fetching preferred languages
                raw_snippets = api.fetch(video_id, languages=lang_codes)
            except Exception:
                try:
                    # Try listing transcripts to find any accessible transcript or auto-generated
                    transcript_list = api.list(video_id)
                    found = None
                    for t in transcript_list:
                        if t.language_code in lang_codes:
                            found = t
                            break
                    if not found:
                        for t in transcript_list:
                            found = t
                            break
                    if found:
                        raw_snippets = found.fetch()
                except Exception as list_err:
                    logger.debug(f"transcript_list failed: {list_err}")

            if raw_snippets:
                # Process fetched transcript snippets
                for item in raw_snippets:
                    # Item could be dict or object with text, start, duration
                    t_text = item.get("text") if isinstance(item, dict) else getattr(item, "text", "")
                    t_start = item.get("start") if isinstance(item, dict) else getattr(item, "start", 0.0)
                    t_dur = item.get("duration") if isinstance(item, dict) else getattr(item, "duration", 0.0)
                    t_text = str(t_text or "").strip()
                    if t_text:
                        time_str = _seconds_to_time_str(float(t_start or 0.0))
                        snippets.append(
                            TranscriptSnippet(
                                text=t_text,
                                start=float(t_start or 0.0),
                                duration=float(t_dur or 0.0),
                                time_str=time_str,
                            )
                        )
                full_text = " ".join(s.text for s in snippets)
                return snippets, full_text, None

            error_msg = "No accessible transcripts were returned by YouTube for this video."

        except Exception as exc:
            err_str = str(exc)
            if "IpBlocked" in type(exc).__name__ or "blocking requests" in err_str:
                error_msg = (
                    "YouTube blocked automated transcript fetching from this network IP. "
                    "You can paste the video transcript or summary directly below to continue full AI analysis."
                )
            elif "TranscriptsDisabled" in type(exc).__name__:
                error_msg = "Subtitles/transcripts are disabled for this YouTube video."
            elif "NoTranscriptFound" in type(exc).__name__:
                error_msg = "No subtitles/transcripts found in the requested language."
            else:
                error_msg = f"Unable to fetch transcript automatically: {err_str[:160]}"

        return snippets, full_text, error_msg

    @classmethod
    def parse_user_provided_transcript(cls, raw_text: str) -> tuple[list[TranscriptSnippet], str]:
        """
        Parses transcripts provided by the user (e.g. copied from YouTube transcript drawer).
        Handles formats like:
          0:00 Welcome to the video
          0:15 In this lesson...
          or
          00:00 - Introduction
          01:30 - Concepts
          or plain paragraphs without timestamps.
        """
        snippets: list[TranscriptSnippet] = []
        cleaned_text = raw_text.strip()
        if not cleaned_text:
            return snippets, ""

        lines = [line.strip() for line in cleaned_text.splitlines() if line.strip()]

        # Pattern for timestamp line or prefix e.g. "0:05", "00:12", "1:23:45", "[01:30]"
        ts_pattern = re.compile(r"^\[?(\d{1,2}:\d{2}(?::\d{2})?)\]?\s*(?:[-–—]\s*)?(.*)$")

        current_time = 0.0
        current_time_str = "00:00"

        i = 0
        while i < len(lines):
            line = lines[i]
            match = ts_pattern.match(line)
            if match:
                ts_str = match.group(1)
                text_part = match.group(2).strip()
                seconds = _time_str_to_seconds(ts_str)
                current_time = seconds
                current_time_str = _seconds_to_time_str(seconds)

                if text_part:
                    snippets.append(
                        TranscriptSnippet(
                            text=text_part,
                            start=current_time,
                            duration=5.0,
                            time_str=current_time_str,
                        )
                    )
                else:
                    # Look ahead to next line for the text
                    if i + 1 < len(lines):
                        next_line = lines[i + 1]
                        if not ts_pattern.match(next_line):
                            snippets.append(
                                TranscriptSnippet(
                                    text=next_line,
                                    start=current_time,
                                    duration=5.0,
                                    time_str=current_time_str,
                                )
                            )
                            i += 1
            else:
                # Plain line without timestamp
                snippets.append(
                    TranscriptSnippet(
                        text=line,
                        start=current_time,
                        duration=5.0,
                        time_str=current_time_str,
                    )
                )
                current_time += 10.0
                current_time_str = _seconds_to_time_str(current_time)
            i += 1

        full_text = " ".join(s.text for s in snippets)
        return snippets, full_text


# ── 2. PERSONALIZED TEACHING & UNDERSTANDING SERVICE ──────────────────────────

class PersonalizedTeachingService:
    """Generates structured topic breakdowns, explanations, and key takeaways."""

    @classmethod
    def build_analysis_prompt(
        cls,
        title: str,
        transcript: str,
        language: str,
        level: str,
        style: str,
        snippets: list[TranscriptSnippet],
    ) -> str:
        # Build timestamp sample to ground topics accurately
        sample_snippets = snippets[:60]
        snippet_lines = [f"[{s.time_str}] {s.text}" for s in sample_snippets]
        sample_context = "\n".join(snippet_lines[:30])

        language_instruction = {
            "English": "Deliver the lesson in clear, engaging, professional English.",
            "Tamil": (
                "Deliver the explanation in pure and natural Tamil (தமிழ் script). "
                "Keep technical terms transliterated or clear in Tamil."
            ),
            "Tanglish": (
                "Deliver the explanation in natural conversational Tanglish (Tamil language written using the English alphabet). "
                "Example style: 'Indha video-la explain pandra main concept enna-na...'. Use English for technical keywords."
            ),
            "Auto": "Deliver the explanation in the language that best fits the audience, defaulting to English.",
        }.get(language, "Deliver the lesson in clear English.")

        level_instruction = {
            "Beginner": "Target a beginner learner. Use relatable analogies, demystify technical jargon, and focus on intuition.",
            "Intermediate": "Target an intermediate learner. Focus on working mechanics, practical syntax, architectural structure, and real-world implementation.",
            "Advanced": "Target an advanced practitioner. Emphasize internal algorithms, performance trade-offs, edge cases, failure modes, and architectural implications.",
        }.get(level, "Target an intermediate learner.")

        style_instruction = {
            "Simple explanation": "Keep it concise, intuitive, and crystal clear with minimal complexity.",
            "Step-by-step": "Break everything down into logically ordered, actionable steps (Step 1, Step 2, etc.).",
            "Practical examples": "Provide concrete real-world code snippets, usage scenarios, or practical walk-throughs.",
            "Technical deep dive": "Provide an in-depth, rigorous architectural breakdown with high technical specificity.",
        }.get(style, "Step-by-step.")

        prompt = f"""You are JARVIS 24, an advanced AI tutor and technical learning assistant.
Analyze the following YouTube video content and provide a high-impact personalized lesson.

VIDEO TITLE: {title}

LEARNER SETTINGS:
- Language: {language} ({language_instruction})
- Learning Level: {level} ({level_instruction})
- Teaching Style: {style} ({style_instruction})

AVAILABLE TRANSCRIPT / CONTENT (with real timestamps):
\"\"\"
{sample_context if sample_context else transcript[:3000]}
\"\"\"

CRITICAL GROUNDING RULES:
1. Ground your facts strictly on the video content above. Do NOT invent fake timestamps or attributes that did not exist in the video.
2. In your explanation, clearly distinguish between:
   - **[Video Facts]**: Concepts, demonstrations, or statements made in the video (include timestamp references like [01:45] when available).
   - **[JARVIS Expansion]**: Value-add context, architectural tips, industry best practices, or deeper background added by JARVIS.
3. Respond ONLY with a valid JSON object matching the following schema without any extra markdown ticks or surrounding text:

{{
  "summary": "2-3 concise sentences summarizing what this video teaches",
  "topics": [
    {{
      "title": "Topic title",
      "time_str": "MM:SS",
      "seconds": 0.0,
      "summary": "Brief 1-sentence topic summary"
    }}
  ],
  "detailed_explanation": "# Markdown formatted comprehensive explanation\\n\\n### Key Concepts\\n...\\n\\n### [Video Facts]\\n...\\n\\n### [JARVIS Expansion]\\n...",
  "key_takeaways": [
    "Core takeaway 1",
    "Core takeaway 2",
    "Core takeaway 3"
  ]
}}
"""
        return prompt

    @classmethod
    def analyze_video(
        cls,
        title: str,
        transcript: str,
        language: str,
        level: str,
        style: str,
        snippets: list[TranscriptSnippet],
        llm: Optional[BaseLLMProvider] = None,
    ) -> tuple[str, list[TopicBreakdown], str, list[str]]:
        """Executes LLM analysis and returns (summary, topics, detailed_explanation, key_takeaways)."""
        provider = llm or get_llm_provider()
        prompt = cls.build_analysis_prompt(title, transcript, language, level, style, snippets)

        try:
            raw_response = provider.generate(prompt=prompt, system="You are an expert AI tutor outputting clean JSON.")
            cleaned = raw_response.strip()
            if cleaned.startswith("```"):
                cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
                cleaned = re.sub(r"\s*```$", "", cleaned)
            parsed = json.loads(cleaned)

            summary = parsed.get("summary", f"Analysis of {title}")
            raw_topics = parsed.get("topics", [])
            topics: list[TopicBreakdown] = []
            for t in raw_topics:
                time_str = t.get("time_str", "00:00")
                secs = float(t.get("seconds", _time_str_to_seconds(time_str)))
                topics.append(
                    TopicBreakdown(
                        title=t.get("title", "Topic"),
                        time_str=time_str,
                        seconds=secs,
                        summary=t.get("summary", ""),
                    )
                )

            # Fallback if no topics parsed from LLM
            if not topics and snippets:
                # Build 3-4 natural milestone topics from snippets
                step = max(1, len(snippets) // 4)
                for idx in range(0, min(len(snippets), step * 4), step):
                    s = snippets[idx]
                    topics.append(
                        TopicBreakdown(
                            title=f"Section: {s.text[:30]}...",
                            time_str=s.time_str,
                            seconds=s.start,
                            summary=s.text[:80],
                        )
                    )

            explanation = parsed.get("detailed_explanation", "")
            if not explanation:
                explanation = f"## Lesson on {title}\n\n{summary}\n\n### Transcript Insights\n{transcript[:800]}"

            takeaways = parsed.get("key_takeaways", [])
            if not takeaways:
                takeaways = [
                    f"Understanding foundational concepts from {title}",
                    "Applying structured patterns learned in the video",
                    "Synthesizing key implementation details",
                ]

            return summary, topics, explanation, takeaways

        except Exception as exc:
            logger.warning(f"LLM analysis failed, falling back to deterministic extraction: {exc}")
            # Deterministic fallback
            summary = f"Summary of '{title}': Key concepts and walkthrough extracted from video content."
            topics = []
            if snippets:
                step = max(1, len(snippets) // 3)
                for idx in range(0, min(len(snippets), step * 3), step):
                    s = snippets[idx]
                    topics.append(
                        TopicBreakdown(
                            title=f"Segment at {s.time_str}",
                            time_str=s.time_str,
                            seconds=s.start,
                            summary=s.text[:100],
                        )
                    )
            explanation = (
                f"# YouTube AI Learning: {title}\n\n"
                f"### [Video Facts]\n"
                f"- **Title**: {title}\n"
                f"- **Language Mode**: {language}\n"
                f"- **Instruction Level**: {level}\n\n"
                f"### Core Overview\n"
                f"{transcript[:600]}...\n\n"
                f"### [JARVIS Expansion]\n"
                f"- To reinforce these concepts, practice building a hands-on proof of concept.\n"
                f"- Test edge cases and observe real-world performance metrics.\n"
            )
            takeaways = [
                f"Key concepts extracted from {title}",
                "Step-by-step review of video transcript notes",
                "Self-paced learning supported with JARVIS interactive Q&A",
            ]
            return summary, topics, explanation, takeaways


# ── 3. ARTIFACT GENERATION SERVICE (QUIZ, FLASHCARDS, NOTES, PDF, PPTX) ──────

class LearningArtifactService:
    """Generates structured quizzes, flashcards, comprehensive notes, PDF and PPTX files."""

    @classmethod
    def generate_quiz(
        cls,
        title: str,
        summary: str,
        transcript: str,
        llm: Optional[BaseLLMProvider] = None,
    ) -> list[QuizQuestion]:
        provider = llm or get_llm_provider()
        prompt = f"""Generate a 4-question multiple-choice quiz based on this YouTube video.
VIDEO: {title}
SUMMARY: {summary}
CONTENT: {transcript[:2500]}

Respond ONLY with a JSON array in this exact schema without extra text:
[
  {{
    "question": "What is ...?",
    "options": ["Option A", "Option B", "Option C", "Option D"],
    "answer_index": 0,
    "explanation": "Why Option A is correct based on the video"
  }}
]"""
        try:
            raw = provider.generate(prompt=prompt, system="Generate a strict JSON quiz array.")
            cleaned = raw.strip()
            if cleaned.startswith("```"):
                cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
                cleaned = re.sub(r"\s*```$", "", cleaned)
            data = json.loads(cleaned)
            questions: list[QuizQuestion] = []
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        questions.append(QuizQuestion.from_dict(item))
            if questions:
                return questions
        except Exception as e:
            logger.warning(f"Quiz generation failed: {e}")

        # Deterministic fallback quiz
        return [
            QuizQuestion(
                question=f"What is the primary topic explored in '{title}'?",
                options=[
                    title,
                    "Unrelated peripheral tooling",
                    "Historical background only",
                    "Abstract speculation",
                ],
                answer_index=0,
                explanation=f"The video specifically focuses on {title}.",
            ),
            QuizQuestion(
                question="How does JARVIS recommend applying the concepts in this video?",
                options=[
                    "Passive observation only",
                    "Hands-on practice and reviewing grounded video notes",
                    "Memorizing without understanding",
                    "Skipping core fundamentals",
                ],
                answer_index=1,
                explanation="Active experimentation and notes review ensure mastery.",
            ),
        ]

    @classmethod
    def generate_flashcards(
        cls,
        title: str,
        summary: str,
        transcript: str,
        llm: Optional[BaseLLMProvider] = None,
    ) -> list[Flashcard]:
        provider = llm or get_llm_provider()
        prompt = f"""Generate 4 study flashcards based on this YouTube video.
VIDEO: {title}
SUMMARY: {summary}
CONTENT: {transcript[:2500]}

Respond ONLY with a JSON array in this exact schema:
[
  {{
    "front": "Key Term or Question",
    "back": "Clear concise answer or definition",
    "topic": "Core Subject"
  }}
]"""
        try:
            raw = provider.generate(prompt=prompt, system="Generate a strict JSON flashcard array.")
            cleaned = raw.strip()
            if cleaned.startswith("```"):
                cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
                cleaned = re.sub(r"\s*```$", "", cleaned)
            data = json.loads(cleaned)
            cards: list[Flashcard] = []
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        cards.append(Flashcard.from_dict(item))
            if cards:
                return cards
        except Exception as e:
            logger.warning(f"Flashcard generation failed: {e}")

        return [
            Flashcard(
                front=f"Core Objective of {title}",
                back=summary[:150] if summary else "Master the topic taught in the video.",
                topic="Overview",
            ),
            Flashcard(
                front="Grounded Video Knowledge",
                back="Facts directly sourced from video captions and presenter explanations.",
                topic="Video Fact",
            ),
            Flashcard(
                front="JARVIS Value-Add",
                back="Practical extensions, architectural guidelines, and technical depth.",
                topic="JARVIS Expansion",
            ),
        ]

    @classmethod
    def generate_notes_markdown(cls, session: YouTubeSession) -> str:
        topics_md = "\n".join(
            [f"- **[{t.time_str}] {t.title}**: {t.summary}" for t in session.topics]
        )
        takeaways_md = "\n".join([f"- {item}" for item in session.key_takeaways])
        notes = f"""# JARVIS 24 — AI Learning Dossier: {session.title}

**Author**: {session.author or 'YouTube Creator'}  
**Video URL**: [{session.video_url}]({session.video_url})  
**Language**: {session.language} | **Level**: {session.level} | **Style**: {session.style}  
**Date**: {session.created_at[:10]}  

---

## 📌 Executive Summary
{session.summary}

---

## ⏱️ Video Topics & Timestamps
{topics_md if topics_md else 'Topics extracted from video overview.'}

---

## 📖 Detailed Personalized Explanation
{session.detailed_explanation}

---

## 💡 Key Takeaways
{takeaways_md if takeaways_md else '- Complete understanding of video concepts.'}
"""
        return notes

    @classmethod
    def export_pdf(cls, session: YouTubeSession) -> bytes:
        """Generates a professional PDF document with reportlab."""
        from reportlab.lib.pagesizes import letter
        from reportlab.lib import colors
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

        buf = io.BytesIO()
        doc = SimpleDocTemplate(
            buf,
            pagesize=letter,
            rightMargin=40,
            leftMargin=40,
            topMargin=40,
            bottomMargin=40,
        )

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            "DocTitle",
            parent=styles["Heading1"],
            fontSize=20,
            leading=24,
            textColor=colors.HexColor("#0284c7"),
            spaceAfter=6,
        )
        h2_style = ParagraphStyle(
            "DocH2",
            parent=styles["Heading2"],
            fontSize=14,
            leading=18,
            textColor=colors.HexColor("#0f172a"),
            spaceBefore=12,
            spaceAfter=6,
        )
        meta_style = ParagraphStyle(
            "DocMeta",
            parent=styles["Normal"],
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#475569"),
        )
        body_style = ParagraphStyle(
            "DocBody",
            parent=styles["Normal"],
            fontSize=10,
            leading=15,
            textColor=colors.HexColor("#1e293b"),
            spaceAfter=6,
        )

        story = []
        story.append(Paragraph(f"JARVIS 24: {session.title}", title_style))
        story.append(
            Paragraph(
                f"<b>Author:</b> {session.author or 'YouTube Creator'} | "
                f"<b>Language:</b> {session.language} | "
                f"<b>Level:</b> {session.level} | "
                f"<b>Style:</b> {session.style}",
                meta_style,
            )
        )
        story.append(Spacer(1, 10))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#0284c7"), spaceAfter=12))

        # Summary
        story.append(Paragraph("Executive Summary", h2_style))
        story.append(Paragraph(session.summary or "Summary of the analyzed video lesson.", body_style))
        story.append(Spacer(1, 8))

        # Topics
        if session.topics:
            story.append(Paragraph("Topic Breakdown & Timestamps", h2_style))
            for t in session.topics:
                story.append(
                    Paragraph(f"<b>[{t.time_str}] {t.title}</b> — {t.summary}", body_style)
                )
            story.append(Spacer(1, 8))

        # Explanation (strip complex markdown for basic reportlab paragraph)
        story.append(Paragraph("Personalized Lesson Explanation", h2_style))
        raw_exp = session.detailed_explanation
        lines = [line.strip() for line in raw_exp.splitlines() if line.strip()]
        for line in lines[:30]:
            clean_line = re.sub(r"[#*_`]", "", line)
            story.append(Paragraph(clean_line, body_style))

        # Key Takeaways
        if session.key_takeaways:
            story.append(Spacer(1, 8))
            story.append(Paragraph("Key Takeaways", h2_style))
            for k in session.key_takeaways:
                story.append(Paragraph(f"• {k}", body_style))

        doc.build(story)
        return buf.getvalue()

    @classmethod
    def export_pptx(cls, session: YouTubeSession) -> bytes:
        """Generates a structured presentation deck with python-pptx."""
        from pptx import Presentation
        from pptx.util import Inches, Pt
        from pptx.dml.color import RGBColor

        prs = Presentation()
        prs.slide_width = Inches(10)
        prs.slide_height = Inches(5.625)  # 16:9

        # Slide 1: Title Slide
        slide_layout = prs.slide_layouts[0]
        slide = prs.slides.add_slide(slide_layout)
        title = slide.shapes.title
        subtitle = slide.placeholders[1]
        title.text = session.title[:60]
        subtitle.text = (
            f"JARVIS 24 AI Learning Masterclass\n"
            f"Author: {session.author or 'YouTube Creator'} | Language: {session.language} | Level: {session.level}"
        )

        # Slide 2: Executive Summary
        bullet_layout = prs.slide_layouts[1]
        slide = prs.slides.add_slide(bullet_layout)
        slide.shapes.title.text = "Executive Summary"
        tf = slide.shapes.placeholders[1].text_frame
        tf.text = session.summary
        tf.fit_text()

        # Slide 3: Topic Breakdown
        if session.topics:
            slide = prs.slides.add_slide(bullet_layout)
            slide.shapes.title.text = "Video Topic Breakdown"
            tf = slide.shapes.placeholders[1].text_frame
            tf.clear()
            for t in session.topics[:6]:
                p = tf.add_paragraph()
                p.text = f"[{t.time_str}] {t.title}: {t.summary}"
                p.level = 0

        # Slide 4: Key Takeaways
        if session.key_takeaways:
            slide = prs.slides.add_slide(bullet_layout)
            slide.shapes.title.text = "Key Takeaways"
            tf = slide.shapes.placeholders[1].text_frame
            tf.clear()
            for k in session.key_takeaways[:5]:
                p = tf.add_paragraph()
                p.text = k
                p.level = 0

        buf = io.BytesIO()
        prs.save(buf)
        return buf.getvalue()


# ── 4. GROUNDED Q&A SERVICE ───────────────────────────────────────────────────

class GroundedQAService:
    """Answers user questions strictly grounded in the video's transcript and content."""

    @classmethod
    def answer_question(
        cls,
        session: YouTubeSession,
        question: str,
        llm: Optional[BaseLLMProvider] = None,
    ) -> QATurn:
        provider = llm or get_llm_provider()

        # Find any matching snippets with timestamps
        q_words = [w.lower() for w in re.findall(r"\w+", question) if len(w) > 3]
        matched_timestamps: list[str] = []
        for s in session.transcript_snippets:
            s_lower = s.text.lower()
            if any(w in s_lower for w in q_words):
                if s.time_str not in matched_timestamps:
                    matched_timestamps.append(s.time_str)
                    if len(matched_timestamps) >= 4:
                        break

        prompt = f"""You are JARVIS 24, an expert AI tutor. Answer the user's question specifically regarding this YouTube video.

VIDEO TITLE: {session.title}
LANGUAGE: {session.language}
LEVEL: {session.level}
TRANSCRIPT SUMMARY: {session.summary}
TRANSCRIPT EXCERPTS:
\"\"\"
{session.full_transcript[:3500]}
\"\"\"

USER QUESTION: {question}

STRICT GROUNDING REQUIREMENTS:
1. First state what the video specifically said about this question, with exact timestamps if relevant.
2. If the topic was NOT mentioned in the video, explicitly state: "This topic was not directly covered in the video, but here is the technical context..."
3. Distinguish clearly between:
   - **[Video Evidence]**: Facts mentioned in the video.
   - **[JARVIS Additional Analysis]**: Value-add technical context, best practices, or troubleshooting from JARVIS.
4. Respond in {session.language}.

Format your response in clean Markdown.
"""
        try:
            answer = provider.generate(prompt=prompt, system="Answer grounded strictly in video transcript.")
        except Exception as e:
            answer = (
                f"### [Video Evidence]\n"
                f"Based on '{session.title}', the video covers core concepts related to your query.\n\n"
                f"### [JARVIS Additional Analysis]\n"
                f"To expand on '{question}': practice applying the techniques shown in the video and verify against reference documentation."
            )

        # Parse out sections if present
        v_facts = ""
        j_ext = ""
        if "### [Video Evidence]" in answer:
            parts = answer.split("### [JARVIS Additional Analysis]")
            v_facts = parts[0].replace("### [Video Evidence]", "").strip()
            if len(parts) > 1:
                j_ext = parts[1].strip()

        turn = QATurn(
            id=str(uuid.uuid4()),
            question=question,
            answer=answer,
            video_facts=v_facts,
            jarvis_extension=j_ext,
            timestamp_references=matched_timestamps,
        )
        return turn


# ── 5. MAIN YOUTUBE LEARNING SERVICE & PERSISTENCE ────────────────────────────

class YouTubeLearningService:
    """
    Main entry point for YouTube AI Learning subsystem.
    Persists lessons in SQLite with thread-safe queries and manages history.
    """

    def __init__(self, db_path: Optional[str | Path] = None):
        if db_path is None:
            base_dir = Path(__file__).resolve().parent.parent
            self.db_path = base_dir / "data" / "cyber_intel.db"
        else:
            self.db_path = Path(db_path).resolve()

        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._lock = threading.Lock()
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(
                str(self.db_path),
                timeout=30.0,
                check_same_thread=False,
            )
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode = WAL;")
            conn.execute("PRAGMA synchronous = NORMAL;")
            conn.execute("PRAGMA busy_timeout = 10000;")
            self._local.conn = conn
        return conn

    def _init_db(self) -> None:
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS youtube_learning_sessions (
                    id                  TEXT PRIMARY KEY,
                    video_id            TEXT NOT NULL,
                    video_url           TEXT NOT NULL,
                    title               TEXT NOT NULL,
                    author              TEXT DEFAULT '',
                    thumbnail_url       TEXT DEFAULT '',
                    language            TEXT NOT NULL DEFAULT 'English',
                    level               TEXT NOT NULL DEFAULT 'Intermediate',
                    style               TEXT NOT NULL DEFAULT 'Step-by-step',
                    has_transcript      INTEGER NOT NULL DEFAULT 1,
                    summary             TEXT DEFAULT '',
                    detailed_explanation TEXT DEFAULT '',
                    session_json        TEXT NOT NULL,
                    created_at          TEXT NOT NULL,
                    updated_at          TEXT NOT NULL
                )
                """
            )
            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_yt_sessions_video_id
                ON youtube_learning_sessions(video_id);
                """
            )
            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_yt_sessions_created_at
                ON youtube_learning_sessions(created_at DESC);
                """
            )
            conn.commit()

    def analyze_and_create_session(
        self,
        url: str,
        language: str = "English",
        level: str = "Intermediate",
        style: str = "Step-by-step",
        user_transcript: Optional[str] = None,
        llm: Optional[BaseLLMProvider] = None,
    ) -> tuple[YouTubeSession, Optional[str]]:
        """
        Validates URL, retrieves metadata and transcripts, performs personalized analysis,
        generates artifacts, and persists the session to SQLite.
        Returns (session, warning_or_error_msg).
        """
        video_id = TranscriptService.extract_video_id(url)
        if not video_id:
            raise ValueError(f"Invalid YouTube URL or Video ID: '{url}'")

        # 1. Retrieve metadata
        meta = TranscriptService.fetch_metadata(video_id)

        # 2. Retrieve or parse transcripts
        notice: Optional[str] = None
        if user_transcript and user_transcript.strip():
            snippets, full_text = TranscriptService.parse_user_provided_transcript(user_transcript)
            has_transcript = True
        else:
            snippets, full_text, fetch_err = TranscriptService.fetch_transcript(video_id, preferred_lang=language)
            has_transcript = len(snippets) > 0
            if fetch_err:
                notice = fetch_err

        # If no transcript available, provide baseline notes from title/metadata
        if not full_text:
            full_text = f"Video title: {meta.title}. Author: {meta.author}."

        # 3. Analyze video
        summary, topics, explanation, takeaways = PersonalizedTeachingService.analyze_video(
            title=meta.title,
            transcript=full_text,
            language=language,
            level=level,
            style=style,
            snippets=snippets,
            llm=llm,
        )

        # 4. Generate initial quiz and flashcards
        quiz = LearningArtifactService.generate_quiz(meta.title, summary, full_text, llm=llm)
        flashcards = LearningArtifactService.generate_flashcards(meta.title, summary, full_text, llm=llm)

        session_id = str(uuid.uuid4())
        session = YouTubeSession(
            id=session_id,
            video_id=video_id,
            video_url=meta.url,
            title=meta.title,
            author=meta.author,
            thumbnail_url=meta.thumbnail_url,
            language=language,
            level=level,
            style=style,
            has_transcript=has_transcript,
            transcript_snippets=snippets,
            full_transcript=full_text,
            topics=topics,
            summary=summary,
            detailed_explanation=explanation,
            key_takeaways=takeaways,
            quiz=quiz,
            flashcards=flashcards,
            notes_markdown="",
            qa_turns=[],
        )

        session.notes_markdown = LearningArtifactService.generate_notes_markdown(session)

        # 5. Persist to SQLite
        self.save_session(session)
        return session, notice

    def save_session(self, session: YouTubeSession) -> None:
        session.updated_at = utc_now_iso()
        session_json = json.dumps(session.to_dict())
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO youtube_learning_sessions (
                    id, video_id, video_url, title, author, thumbnail_url,
                    language, level, style, has_transcript, summary,
                    detailed_explanation, session_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    title=excluded.title,
                    author=excluded.author,
                    thumbnail_url=excluded.thumbnail_url,
                    language=excluded.language,
                    level=excluded.level,
                    style=excluded.style,
                    has_transcript=excluded.has_transcript,
                    summary=excluded.summary,
                    detailed_explanation=excluded.detailed_explanation,
                    session_json=excluded.session_json,
                    updated_at=excluded.updated_at
                """,
                (
                    session.id,
                    session.video_id,
                    session.video_url,
                    session.title,
                    session.author,
                    session.thumbnail_url,
                    session.language,
                    session.level,
                    session.style,
                    1 if session.has_transcript else 0,
                    session.summary,
                    session.detailed_explanation,
                    session_json,
                    session.created_at,
                    session.updated_at,
                ),
            )
            conn.commit()

    def get_session(self, session_id: str) -> Optional[YouTubeSession]:
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute(
                "SELECT session_json FROM youtube_learning_sessions WHERE id = ?",
                (session_id,),
            )
            row = cursor.fetchone()
            if not row:
                return None
            try:
                data = json.loads(row["session_json"])
                return YouTubeSession.from_dict(data)
            except Exception as e:
                logger.error(f"Error deserializing session {session_id}: {e}")
                return None

    def list_sessions(
        self,
        search: str = "",
        language: Optional[str] = None,
        level: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()

            query = (
                "SELECT id, video_id, video_url, title, author, thumbnail_url, "
                "language, level, style, has_transcript, summary, created_at, updated_at "
                "FROM youtube_learning_sessions WHERE 1=1"
            )
            params: list[Any] = []

            if search and search.strip():
                query += " AND (title LIKE ? OR summary LIKE ? OR author LIKE ?)"
                pattern = f"%{search.strip()}%"
                params.extend([pattern, pattern, pattern])

            if language and language != "ALL":
                query += " AND language = ?"
                params.append(language)

            if level and level != "ALL":
                query += " AND level = ?"
                params.append(level)

            query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])

            cursor.execute(query, params)
            rows = cursor.fetchall()
            return [dict(r) for r in rows]

    def delete_session(self, session_id: str) -> bool:
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute(
                "DELETE FROM youtube_learning_sessions WHERE id = ?",
                (session_id,),
            )
            conn.commit()
            return cursor.rowcount > 0

    def ask_question(
        self, session_id: str, question: str, llm: Optional[BaseLLMProvider] = None
    ) -> QATurn:
        session = self.get_session(session_id)
        if not session:
            raise KeyError(f"Session '{session_id}' not found.")

        turn = GroundedQAService.answer_question(session, question, llm=llm)
        session.qa_turns.append(turn)
        self.save_session(session)
        return turn

    def close(self) -> None:
        """Close thread-local SQLite connection."""
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
            self._local.conn = None


_service_singleton: Optional[YouTubeLearningService] = None
_singleton_lock = threading.Lock()


def get_youtube_learning_service() -> YouTubeLearningService:
    global _service_singleton
    if _service_singleton is None:
        with _singleton_lock:
            if _service_singleton is None:
                _service_singleton = YouTubeLearningService()
    return _service_singleton
