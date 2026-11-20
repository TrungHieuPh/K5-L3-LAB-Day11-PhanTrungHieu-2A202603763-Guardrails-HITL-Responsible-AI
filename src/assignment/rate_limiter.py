"""
Assignment 11 — Rate Limiter.

Sliding-window, per-user rate limiting. Blocks abuse that other
guardrail layers do not address (flooding / cost attacks).
"""
from __future__ import annotations

from collections import defaultdict, deque
import time

from google.adk.plugins import base_plugin
from google.genai import types


class RateLimitPlugin(base_plugin.BasePlugin):
    """Block users who exceed max_requests within window_seconds."""

    def __init__(self, max_requests: int = 10, window_seconds: int = 60):
        super().__init__(name="rate_limiter")
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        # Mỗi user có 1 hàng đợi chứa thời điểm các request còn nằm trong cửa sổ.
        self.user_windows: dict[str, deque] = defaultdict(deque)
        self.blocked_count = 0
        self.total_count = 0

    def _block_response(self, message: str) -> types.Content:
        return types.Content(
            role="model",
            parts=[types.Part.from_text(text=message)],
        )

    async def on_user_message_callback(self, *, invocation_context, user_message):
        """Return Content to block, or None to allow."""
        self.total_count += 1
        user_id = getattr(invocation_context, "user_id", None) or "anonymous"
        now = time.time()
        window = self.user_windows[user_id]

        # 1. Bỏ các request đã cũ hơn window_seconds (trượt cửa sổ về hiện tại).
        while window and window[0] <= now - self.window_seconds:
            window.popleft()

        # 2. Đã đủ max_requests trong cửa sổ → chặn, KHÔNG ghi thêm timestamp
        #    (request bị chặn không chiếm chỗ trong quota).
        if len(window) >= self.max_requests:
            wait = self.window_seconds - (now - window[0])
            self.blocked_count += 1
            return self._block_response(
                f"Rate limit exceeded. Try again in {max(wait, 0):.0f}s."
            )

        # 3. Còn quota → ghi lại thời điểm và cho qua.
        window.append(now)
        return None
