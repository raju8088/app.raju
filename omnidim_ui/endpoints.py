from __future__ import annotations

import re
from typing import Any

_TEMPLATE_REGEX_CACHE: dict[str, re.Pattern[str]] = {}


def endpoint_id(method: str, path: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", f"{method}-{path}".lower()).strip("-")


def ep(
    group: str,
    method: str,
    path: str,
    summary: str,
    body: object = None,
    query: dict[str, Any] | None = None,
    note: str = "",
    danger: bool = False,
) -> dict[str, Any]:
    method = method.upper()
    return {
        "id": endpoint_id(method, path),
        "group": group,
        "method": method,
        "path": path,
        "summary": summary,
        "bodyExample": body,
        "queryExample": query or {},
        "note": note,
        "danger": danger,
        "pathParams": re.findall(r"{([^}]+)}", path),
    }


GROUPS: list[dict[str, Any]] = [
    {
        "name": "Sessions",
        "description": "Create temporary browser voice sessions and receive a WebSocket URL.",
        "endpoints": [
            ep("Sessions", "POST", "/sessions/create", "Create session", {"agent_id": 158910}),
        ],
    },
    {
        "name": "Agents",
        "description": "Create, inspect, update, delete, and version AI voice agents.",
        "endpoints": [
            ep("Agents", "GET", "/agents", "List agents", query={"pageno": 1, "pagesize": 30}),
            ep(
                "Agents",
                "POST",
                "/agents/create",
                "Create agent",
                {
                    "name": "Customer Support Agent",
                    "welcome_message": "Hello! I am your support assistant. How can I help you today?",
                    "context_breakdown": [
                        {
                            "title": "Purpose",
                            "body": "This agent helps customers with product questions and support issues.",
                        }
                    ],
                },
            ),
            ep("Agents", "GET", "/agents/{agent_id}", "Get agent"),
            ep(
                "Agents",
                "PUT",
                "/agents/{agent_id}",
                "Update agent",
                {
                    "name": "Updated Support Agent",
                    "welcome_message": "Hello! I am your updated support assistant. How can I help you today?",
                    "context_breakdown": [
                        {
                            "title": "Purpose",
                            "body": "This agent helps customers with product questions and support issues.",
                        }
                    ],
                },
            ),
            ep("Agents", "DELETE", "/agents/{agent_id}", "Delete agent", danger=True),
            ep("Agents", "GET", "/agents/{agent_id}/versions", "List agent versions", query={"pageno": 1, "pagesize": 30}),
            ep(
                "Agents",
                "POST",
                "/agents/{agent_id}/versions",
                "Save an agent version",
                {"name": "Working version", "note": "Saved before editing the prompt."},
            ),
            ep(
                "Agents",
                "PATCH",
                "/agents/{agent_id}/versions/{version_number}",
                "Rename an agent version",
                {"name": "Pre-launch version", "note": "Reviewed and renamed."},
            ),
            ep("Agents", "DELETE", "/agents/{agent_id}/versions/{version_number}", "Delete an agent version", danger=True),
            ep("Agents", "GET", "/agents/{agent_id}/versions/{version_number}/diff", "Diff an agent version"),
            ep(
                "Agents",
                "POST",
                "/agents/{agent_id}/versions/{version_number}/restore",
                "Restore an agent version",
                {},
                danger=True,
            ),
        ],
    },
    {
        "name": "Calls",
        "description": "Place one outbound call and review call logs.",
        "endpoints": [
            ep(
                "Calls",
                "POST",
                "/calls/dispatch",
                "Dispatch call",
                {
                    "agent_id": 158910,
                    "to_number": "+15551234567",
                    "from_number_id": 23,
                    "call_context": {
                        "user_name": "Jane Doe",
                        "account_id": "A-2031",
                        "last_order": "2026-04-15",
                    },
                    "metadata": {"crm_lead_id": "lead_9876", "source": "website_form"},
                },
                danger=True,
                note="This can place a real outbound call when your key has call access.",
            ),
            ep("Calls", "GET", "/calls/logs", "List call logs", query={"page": 1, "page_size": 10}),
            ep("Calls", "GET", "/calls/logs/{call_log_id}", "Get call log"),
        ],
    },
    {
        "name": "Bulk Calls",
        "description": "Build and operate campaign calling flows.",
        "endpoints": [
            ep("Bulk Calls", "GET", "/calls/bulk_call", "Fetch bulk calls", query={"pageno": 1, "pagesize": 10, "status": ""}),
            ep(
                "Bulk Calls",
                "POST",
                "/calls/bulk_call/create",
                "Create bulk call",
                {
                    "name": "Customer follow-ups",
                    "phone_number_id": "177",
                    "bot_id": 512,
                    "contact_list": [
                        {"phone_number": "+15551234567", "customer_name": "John Doe", "plan": "pro"},
                        {"phone_number": "+15559876543", "customer_name": "Jane Smith", "plan": "trial"},
                    ],
                    "is_scheduled": False,
                    "concurrent_call_limit": 1,
                    "retry_config": {"auto_retry": False, "auto_retry_schedule": "next_day", "retry_limit": 1},
                },
                danger=True,
            ),
            ep(
                "Bulk Calls",
                "POST",
                "/calls/bulk_call/{campaign_id}/add_contact",
                "Add contact to dynamic campaign",
                {
                    "to_number": "+15551234567",
                    "custom_variables": {"name": "Demo User", "interest": "Home Insurance"},
                    "metadata": {"crm_lead_id": "lead_9876", "source": "website_form"},
                },
                danger=True,
            ),
            ep("Bulk Calls", "GET", "/calls/bulk_call/{bulk_call_id}", "Bulk call details"),
            ep("Bulk Calls", "PUT", "/calls/bulk_call/{bulk_call_id}", "Bulk call actions", {"action": "pause"}, danger=True),
            ep("Bulk Calls", "DELETE", "/calls/bulk_call/{bulk_call_id}", "Cancel bulk call", danger=True),
            ep("Bulk Calls", "GET", "/calls/bulk_call/{bulk_call_id}/lines", "Bulk call results", query={"pagesize": 150, "include_total": True}),
            ep("Bulk Calls", "GET", "/calls/bulk_call/{bulk_call_id}/numbers", "List rotation pool"),
            ep("Bulk Calls", "POST", "/calls/bulk_call/{bulk_call_id}/numbers", "Add number to rotation pool", {"phone_number_id": 178}),
            ep(
                "Bulk Calls",
                "PUT",
                "/calls/bulk_call/{bulk_call_id}/numbers/{assignment_id}",
                "Pause or resume pool number",
                {"is_active": False},
                danger=True,
            ),
            ep(
                "Bulk Calls",
                "POST",
                "/calls/bulk_call/{campaign_id}/add_contacts",
                "Add contacts in bulk",
                {
                    "contacts": [
                        {"to_number": "+15551234567", "custom_variables": {"contact_name": "Ravi"}},
                        {"to_number": "+15559876543", "custom_variables": {"contact_name": "Priya"}},
                    ]
                },
                danger=True,
            ),
            ep("Bulk Calls", "POST", "/calls/bulk_call/{bulk_call_id}/start", "Start a draft campaign", {}, danger=True),
            ep("Bulk Calls", "PUT", "/calls/bulk_call/{bulk_call_id}/concurrency", "Change concurrency", {"concurrent_call_limit": 5}),
            ep(
                "Bulk Calls",
                "POST",
                "/calls/bulk_call/{bulk_call_id}/manual_retry",
                "Retry contacts that did not connect",
                {"line_ids": [156], "retry_after_minutes": 15},
                danger=True,
            ),
            ep(
                "Bulk Calls",
                "PUT",
                "/calls/bulk_call/{bulk_call_id}/daily-time-control",
                "Set calling hours",
                {
                    "enable_daily_auto_start": True,
                    "daily_start_time": "09:00",
                    "daily_start_timezone": "America/New_York",
                    "enable_daily_hard_stop": True,
                    "daily_stop_time": "17:00",
                    "daily_stop_timezone": "America/New_York",
                },
            ),
            ep("Bulk Calls", "GET", "/bulk-call/{bulk_call_id}/live-status", "Bulk call live status"),
        ],
    },
    {
        "name": "Knowledge Base",
        "description": "Upload PDF knowledge files and attach them to agents.",
        "endpoints": [
            ep("Knowledge Base", "GET", "/knowledge_base/list", "List knowledge base files"),
            ep("Knowledge Base", "POST", "/knowledge_base/can_upload", "Check file upload capability", {"file_size": 1048576, "file_type": "application/pdf"}),
            ep(
                "Knowledge Base",
                "POST",
                "/knowledge_base/create",
                "Upload file to knowledge base",
                {"file": "BASE64_PDF_CONTENT", "filename": "sample.pdf"},
                note="Use the file helper in the UI to load a PDF into the JSON body.",
            ),
            ep(
                "Knowledge Base",
                "POST",
                "/knowledge_base/attach",
                "Attach files to agent",
                {"file_ids": [123, 456], "agent_id": 789, "access_description": "Use these files when answering policy questions."},
            ),
            ep("Knowledge Base", "POST", "/knowledge_base/detach", "Detach files from agent", {"file_ids": [123, 456], "agent_id": 789}),
            ep("Knowledge Base", "POST", "/knowledge_base/delete", "Delete file from knowledge base", {"file_id": 123}, danger=True),
        ],
    },
    {
        "name": "Phone Numbers",
        "description": "List, buy, import, attach, and release calling numbers.",
        "endpoints": [
            ep("Phone Numbers", "GET", "/phone_number/list", "List phone numbers", query={"pageno": 1, "pagesize": 30}),
            ep("Phone Numbers", "GET", "/phone_number/search", "Search available phone numbers", query={"region": "US", "carrier": "carrier-1", "pattern": "", "page": 1, "limit": 20}),
            ep(
                "Phone Numbers",
                "POST",
                "/phone_number/purchase",
                "Purchase a phone number",
                {"phone_number": "+15551234567", "region": "US", "carrier": "carrier-1"},
                danger=True,
            ),
            ep("Phone Numbers", "POST", "/phone_number/release", "Release a phone number", {"phone_number_id": 213}, danger=True),
            ep("Phone Numbers", "POST", "/phone_number/attach", "Attach phone number to agent", {"phone_number_id": 213, "agent_id": 158910}),
            ep("Phone Numbers", "POST", "/phone_number/detach", "Detach phone number", {"phone_number_id": 213}),
            ep(
                "Phone Numbers",
                "POST",
                "/phone_number/import/twilio",
                "Import Twilio number",
                {"phone_number": "+15551234567", "account_sid": "ACxxxxxxxx", "auth_token": "twilio_auth_token"},
                danger=True,
            ),
            ep(
                "Phone Numbers",
                "POST",
                "/phone_number/import/exotel",
                "Import Exotel number",
                {
                    "phone_number": "+911234567890",
                    "subdomain": "your-subdomain",
                    "account_sid": "exotel_account_sid",
                    "api_key": "exotel_api_key",
                    "api_token": "exotel_api_token",
                },
                danger=True,
            ),
            ep(
                "Phone Numbers",
                "POST",
                "/phone_number/import/sip",
                "Import SIP trunk",
                {
                    "phone_number": "+15551234567",
                    "sip_host": "sip.example.com",
                    "sip_port": 5060,
                    "sip_username": "username",
                    "sip_password": "password",
                    "sip_trunk_name": "Main trunk",
                },
                danger=True,
            ),
        ],
    },
    {
        "name": "Providers",
        "description": "Discover available LLM, speech-to-text, text-to-speech, and voice options.",
        "endpoints": [
            ep("Providers", "GET", "/providers/llms", "List LLM providers"),
            ep("Providers", "GET", "/providers/voices", "List voices", query={"provider": "", "language": ""}),
            ep("Providers", "GET", "/providers/stt", "List STT providers"),
            ep("Providers", "GET", "/providers/tts", "List TTS providers"),
            ep("Providers", "GET", "/providers/all", "List all providers"),
            ep("Providers", "GET", "/providers/voice/{voice_id}", "Get voice details"),
        ],
    },
    {
        "name": "Simulation",
        "description": "Create and run tests against agents before live calling.",
        "endpoints": [
            ep("Simulation", "GET", "/simulations", "List simulations", query={"page": 1, "page_size": 30}),
            ep(
                "Simulation",
                "POST",
                "/simulations",
                "Create simulation",
                {
                    "name": "Customer Support Test",
                    "agent_id": 158910,
                    "number_of_call_to_make": 1,
                    "concurrent_call_count": 1,
                    "max_call_duration_in_minutes": 3,
                    "scenarios": [
                        {
                            "name": "Polite cancellation",
                            "description": "Ask to cancel a subscription, but be friendly.",
                            "expected_result": "Agent acknowledges the request and routes to retention.",
                            "selected_voices": [{"id": "voice_id_1", "provider": "eleven_labs"}],
                        }
                    ],
                },
            ),
            ep("Simulation", "GET", "/simulations/{simulation_id}", "Get simulation"),
            ep(
                "Simulation",
                "PUT",
                "/simulations/{simulation_id}",
                "Update simulation",
                {"name": "Updated Support Test", "number_of_call_to_make": 1, "concurrent_call_count": 1},
            ),
            ep("Simulation", "DELETE", "/simulations/{simulation_id}", "Delete simulation", danger=True),
            ep("Simulation", "POST", "/simulations/{simulation_id}/start", "Start simulation", {}, danger=True),
            ep("Simulation", "POST", "/simulations/{simulation_id}/stop", "Stop simulation", {}),
            ep("Simulation", "POST", "/simulations/{simulation_id}/enhance-prompt", "Enhance prompt", {"prompt": "Make this test more realistic."}),
        ],
    },
    {
        "name": "Reseller/Admin",
        "description": "Manage child organizations, credits, concurrency, and KYC flows.",
        "endpoints": [
            ep("Reseller/Admin", "GET", "/reseller/organizations", "List child organizations", query={"page": 1, "page_size": 30}),
            ep(
                "Reseller/Admin",
                "POST",
                "/reseller/users/add",
                "Add user",
                {"name": "Demo User", "email": "demo@example.com", "password": "temporary-password"},
                danger=True,
            ),
            ep("Reseller/Admin", "POST", "/reseller/users/access-control", "Update user access control", {"user_id": 1234, "access": {"is_bots_menu_access": True}}, danger=True),
            ep("Reseller/Admin", "POST", "/reseller/users/expiry", "Update user expiry", {"user_id": 1234, "expiry_date": "2026-12-31"}, danger=True),
            ep("Reseller/Admin", "POST", "/reseller/concurrency", "Set child concurrency limit", {"user_id": 1234, "concurrent_call_limit": 3}, danger=True),
            ep("Reseller/Admin", "POST", "/reseller/credits/calculate", "Calculate credit operation", {"user_id": 1234, "credits": 100}),
            ep("Reseller/Admin", "POST", "/reseller/credits/transfer", "Transfer credits to a child", {"user_id": 1234, "credits": 100}, danger=True),
            ep("Reseller/Admin", "POST", "/reseller/credits/revert", "Revert credits", {"user_id": 1234, "credits": 50}, danger=True),
            ep("Reseller/Admin", "GET", "/reseller/credits/logs", "Credit transfer logs", query={"page": 1, "page_size": 30}),
            ep("Reseller/Admin", "GET", "/reseller/kyc/status", "Get KYC status", query={"user_id": 1234}),
            ep("Reseller/Admin", "GET", "/reseller/kyc/requirements", "Get KYC requirements for a region", query={"region": "US", "carrier": "carrier-1"}),
            ep(
                "Reseller/Admin",
                "POST",
                "/reseller/kyc/steps/{step}",
                "Submit a KYC verification step",
                {"user_id": 1234, "region": "US", "carrier": "carrier-1", "name": "Demo User", "email": "demo@example.com", "phone": "+15551234567"},
                danger=True,
            ),
        ],
    },
]

ENDPOINTS: list[dict[str, Any]] = [endpoint for group in GROUPS for endpoint in group["endpoints"]]


def is_dangerous_operation(endpoint: dict[str, Any], body: object = None) -> bool:
    """Classify spend/destructive operations on the server, including body-driven campaign actions."""
    if endpoint.get("danger") or endpoint.get("method") == "DELETE":
        return True
    if isinstance(body, dict) and endpoint.get("method") != "GET":
        action = str(body.get("action", "")).strip().lower()
        if action in {"resume", "start", "restart", "activate", "dispatch", "send", "delete"}:
            return True
    return False


def template_to_regex(template: str) -> re.Pattern[str]:
    if template not in _TEMPLATE_REGEX_CACHE:
        pattern = "^" + re.sub(r"\{([^}]+)\}", r"(?P<\1>[^/?#]+)", template) + "$"
        _TEMPLATE_REGEX_CACHE[template] = re.compile(pattern)
    return _TEMPLATE_REGEX_CACHE[template]


def match_endpoint(method: str, path: str) -> tuple[dict[str, Any] | None, dict[str, str]]:
    method = method.upper()
    if any(c in path for c in ("..", "?", "#", "%", "\\", "//")) or any(ord(c) <= 32 or ord(c) == 127 for c in path):
        raise ValueError(f"Path contains illegal characters: {path}")
    for endpoint in ENDPOINTS:
        if endpoint["method"] != method:
            continue
        regex = template_to_regex(endpoint["path"])
        m = regex.fullmatch(path)
        if m:
            params = m.groupdict()
            for name, val in params.items():
                if any(c in val for c in ("/", "..", "?", "#")) or any(ord(c) < 32 or ord(c) == 127 for c in val):
                    raise ValueError(f"Path parameter '{name}' contains illegal characters: {val}")
            return endpoint, params
    return None, {}
