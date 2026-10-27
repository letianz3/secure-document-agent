# AI assistance and sources

OpenAI Codex (6 Astra), September 2026, assisted with the code, tests, documentation,
architecture, code explanations and report edits. Requests included following the
HW1 and recitation patterns, implementing five security measures, and simplifying
setup after local ML dependencies caused environment conflicts. Adopted outputs
include the implementation, verification scripts, diagram and draft edits.

The final fifth measure is a standard-library rule-based prompt-injection detector.
It replaces the previous DeBERTa implementation. It uses explicit patterns and
Unicode normalization, not learned classification. The student reviews the code and
submission and is responsible for correctness. Tests are not a general accuracy claim.

Sources: course HW1 PDF and recitation exercises 2 and 3 (authorization and guard
placement concepts); Google generateContent API https://ai.google.dev/api/generate-content ;
Python documentation https://docs.python.org/3/library/re.html ,
https://docs.python.org/3/library/unicodedata.html and standard-library unittest,
urllib.request and secrets. No third-party runtime library is required.
