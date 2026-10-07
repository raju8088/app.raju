import json
import logging
import time
import uuid

from django.conf import settings
from django.http import JsonResponse

logger = logging.getLogger("portal.requests")


class JsonFormatter(logging.Formatter):
    def format(self, record):
        # Never include request bodies, query strings, cookies, headers or exception locals.
        return json.dumps({"time": self.formatTime(record), "level": record.levelname,
                           "logger": record.name, "message": record.getMessage()})


class RequestBoundaryMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        request.request_id = uuid.uuid4().hex
        started = time.monotonic()
        request.get_host()  # Validate Host for static pages as well as authenticated APIs.
        try:
            length = int(request.META.get("CONTENT_LENGTH") or "0")
        except ValueError:
            length = -1
        if length < 0 or length > settings.DATA_UPLOAD_MAX_MEMORY_SIZE:
            return JsonResponse({"ok": False, "error": "Invalid or oversized request body."}, status=413)
        response = self.get_response(request)
        response["X-Request-ID"] = request.request_id
        response["Permissions-Policy"] = "camera=(), geolocation=(), microphone=()"
        response["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; "
            "frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
        )
        if not request.path.startswith("/static/"):
            response["Cache-Control"] = "no-store"
        logger.info("request id=%s method=%s status=%d duration_ms=%d", request.request_id,
                    request.method, response.status_code, int((time.monotonic() - started) * 1000))
        return response
