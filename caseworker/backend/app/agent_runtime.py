"""On-demand Google ADK execution used by the Cloud Run API."""

from uuid import uuid4

from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types

from .agent import app


session_service = InMemorySessionService()
runner = Runner(app=app, session_service=session_service)


async def analyze_case(case_id: str, question: str) -> dict[str, str]:
    """Run the ADK orchestrator against a case and return its final response."""

    user_id = "caseworker-api"
    session_id = f"case-{case_id.lower()}-{uuid4().hex}"
    await session_service.create_session(
        app_name=app.name,
        user_id=user_id,
        session_id=session_id,
        state={"case_id": case_id},
    )
    message = types.Content(
        role="user",
        parts=[types.Part(text=f"Case ID: {case_id}\n\nTask: {question}")],
    )
    answer = ""
    invocation_id = ""
    async for event in runner.run_async(
        user_id=user_id,
        session_id=session_id,
        new_message=message,
    ):
        invocation_id = getattr(event, "invocation_id", "") or invocation_id
        if event.is_final_response() and event.content:
            answer = "\n".join(part.text for part in event.content.parts or [] if part.text)
    if not answer:
        raise RuntimeError("The ADK run completed without a final response.")
    return {"answer": answer, "session_id": session_id, "invocation_id": invocation_id}
