#!/usr/bin/env python3
"""
Persistent Rate Limiting Module

Provides file-based rate limiting that persists across process restarts.
This prevents bypassing rate limits by creating multiple instances.
"""

import json
import os
import time
from typing import Dict, Optional
from datetime import datetime, timedelta
import fcntl  # For file locking on Unix systems

class PersistentRateLimiter:
    """File-based persistent rate limiter."""

    def __init__(self,
                 state_file: str = "/tmp/.email_ready_rate_limits.json",
                 window_seconds: int = 3600,  # 1 hour window
                 max_requests: int = 100):
        """
        Initialize rate limiter with persistent storage.

        Args:
            state_file: Path to store rate limit state
            window_seconds: Time window for rate limiting
            max_requests: Maximum requests allowed in window
        """
        self.state_file = state_file
        self.window_seconds = window_seconds
        self.max_requests = max_requests
        self._ensure_state_file()

    def _ensure_state_file(self):
        """Ensure state file exists with proper structure."""
        if not os.path.exists(self.state_file):
            try:
                with open(self.state_file, 'w') as f:
                    json.dump({
                        "domains": {},
                        "global_count": 0,
                        "last_cleanup": time.time()
                    }, f)
                # Set restrictive permissions (owner read/write only)
                os.chmod(self.state_file, 0o600)
            except Exception:
                # Fall back to memory-only if can't create file
                pass

    def _load_state(self) -> Dict:
        """Load rate limit state from file."""
        try:
            with open(self.state_file, 'r') as f:
                # Use file locking to prevent race conditions
                fcntl.flock(f.fileno(), fcntl.LOCK_SH)
                state = json.load(f)
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
                return state
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return {
                "domains": {},
                "global_count": 0,
                "last_cleanup": time.time()
            }

    def _save_state(self, state: Dict):
        """Save rate limit state to file."""
        try:
            # Write to temp file first for atomic operation
            temp_file = f"{self.state_file}.tmp"
            with open(temp_file, 'w') as f:
                # Use file locking
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                json.dump(state, f, indent=2)
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)

            # Atomic rename
            os.replace(temp_file, self.state_file)
            os.chmod(self.state_file, 0o600)
        except Exception:
            # If we can't save, continue without persistence
            pass

    def _cleanup_old_entries(self, state: Dict) -> Dict:
        """Remove expired entries to prevent file growth."""
        current_time = time.time()
        cutoff_time = current_time - self.window_seconds

        # Clean up domain entries
        for domain in list(state["domains"].keys()):
            domain_data = state["domains"][domain]
            # Remove old timestamps
            domain_data["requests"] = [
                req for req in domain_data.get("requests", [])
                if req > cutoff_time
            ]
            # Remove domain if no recent requests
            if not domain_data["requests"]:
                del state["domains"][domain]

        state["last_cleanup"] = current_time
        return state

    def check_rate_limit(self, domain: str,
                         action: str = "dns_query") -> tuple[bool, str]:
        """
        Check if action is allowed under rate limits.

        Args:
            domain: Domain being queried
            action: Type of action (dns_query, smtp_connect, etc)

        Returns:
            (allowed, message) - whether action is allowed and reason
        """
        current_time = time.time()
        state = self._load_state()

        # Cleanup old entries periodically
        if current_time - state.get("last_cleanup", 0) > 300:  # Every 5 minutes
            state = self._cleanup_old_entries(state)

        # Initialize domain entry if needed
        if domain not in state["domains"]:
            state["domains"][domain] = {
                "requests": [],
                "blocked_until": 0
            }

        domain_data = state["domains"][domain]

        # Check if domain is temporarily blocked
        if domain_data.get("blocked_until", 0) > current_time:
            remaining = int(domain_data["blocked_until"] - current_time)
            return False, f"Domain blocked for {remaining} more seconds due to rate limit"

        # Remove old requests outside window
        cutoff_time = current_time - self.window_seconds
        domain_data["requests"] = [
            req for req in domain_data["requests"]
            if req > cutoff_time
        ]

        # Check rate limit
        if len(domain_data["requests"]) >= self.max_requests:
            # Block domain temporarily
            domain_data["blocked_until"] = current_time + 60  # Block for 1 minute
            self._save_state(state)
            return False, f"Rate limit exceeded: {len(domain_data['requests'])}/{self.max_requests} requests in {self.window_seconds}s"

        # Allow request and record it
        domain_data["requests"].append(current_time)
        state["global_count"] += 1
        self._save_state(state)

        requests_used = len(domain_data["requests"])
        requests_remaining = self.max_requests - requests_used
        return True, f"Allowed ({requests_remaining}/{self.max_requests} remaining)"

    def get_rate_limit_status(self, domain: Optional[str] = None) -> Dict:
        """Get current rate limit status."""
        state = self._load_state()
        current_time = time.time()
        cutoff_time = current_time - self.window_seconds

        if domain:
            if domain in state["domains"]:
                domain_data = state["domains"][domain]
                recent_requests = [
                    req for req in domain_data.get("requests", [])
                    if req > cutoff_time
                ]
                return {
                    "domain": domain,
                    "requests_used": len(recent_requests),
                    "requests_limit": self.max_requests,
                    "window_seconds": self.window_seconds,
                    "blocked_until": domain_data.get("blocked_until", 0),
                    "is_blocked": domain_data.get("blocked_until", 0) > current_time
                }
            else:
                return {
                    "domain": domain,
                    "requests_used": 0,
                    "requests_limit": self.max_requests,
                    "window_seconds": self.window_seconds,
                    "blocked_until": 0,
                    "is_blocked": False
                }
        else:
            # Global status
            total_domains = len(state["domains"])
            blocked_domains = sum(
                1 for d in state["domains"].values()
                if d.get("blocked_until", 0) > current_time
            )
            return {
                "total_domains": total_domains,
                "blocked_domains": blocked_domains,
                "global_count": state.get("global_count", 0),
                "window_seconds": self.window_seconds,
                "max_requests_per_domain": self.max_requests
            }

    def reset_limits(self, domain: Optional[str] = None):
        """Reset rate limits (admin function)."""
        state = self._load_state()

        if domain:
            if domain in state["domains"]:
                del state["domains"][domain]
        else:
            # Reset all limits
            state["domains"] = {}
            state["global_count"] = 0

        self._save_state(state)


# Integration with existing code
def create_rate_limiter(config: Optional[Dict] = None) -> PersistentRateLimiter:
    """
    Factory function to create rate limiter with configuration.

    Args:
        config: Optional configuration dict with:
            - state_file: Path to persistence file
            - window_seconds: Time window
            - max_requests: Request limit
    """
    if config is None:
        config = {}

    # Use environment variables for configuration
    state_file = config.get("state_file",
                           os.environ.get("RATE_LIMIT_FILE",
                                        "/tmp/.email_ready_rate_limits.json"))
    window_seconds = config.get("window_seconds",
                               int(os.environ.get("RATE_LIMIT_WINDOW", "3600")))
    max_requests = config.get("max_requests",
                             int(os.environ.get("RATE_LIMIT_MAX", "100")))

    return PersistentRateLimiter(state_file, window_seconds, max_requests)


# Example usage and testing
def main():
    """Test the rate limiter."""
    print("Testing Persistent Rate Limiter")
    print("=" * 40)

    limiter = create_rate_limiter({
        "window_seconds": 60,  # 1 minute window for testing
        "max_requests": 5       # 5 requests per minute for testing
    })

    test_domain = "example.com"

    print(f"\nTesting domain: {test_domain}")
    print(f"Limit: 5 requests per 60 seconds")
    print()

    # Test multiple requests
    for i in range(7):
        allowed, message = limiter.check_rate_limit(test_domain)
        status = "✅" if allowed else "❌"
        print(f"Request {i+1}: {status} {message}")
        time.sleep(0.5)  # Small delay between requests

    # Check status
    print("\nRate limit status:")
    status = limiter.get_rate_limit_status(test_domain)
    for key, value in status.items():
        print(f"  {key}: {value}")

    # Global status
    print("\nGlobal status:")
    global_status = limiter.get_rate_limit_status()
    for key, value in global_status.items():
        print(f"  {key}: {value}")


if __name__ == "__main__":
    main()