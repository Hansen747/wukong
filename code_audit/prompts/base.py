"""Prompt fragments used by the AuditAgent base class."""

# Fallback compression summary template used when no custom factory is provided.
COMPRESSION_FALLBACK_TEMPLATE = (
    "[Context compressed: {compressed_count} earlier messages removed. "
    "I will continue my analysis from where I left off, "
    "tracking which methods I've already analyzed to avoid "
    "duplicates, and submit findings when done.]"
)

# Bridge user message injected after compression summary to maintain
# Anthropic's strict user/assistant alternation.
COMPRESSION_BRIDGE_USER_MESSAGE = "Understood. Please continue."
