#!/usr/bin/env bash
# Shared LLM helper for the auto-reply/auto-review workflows.
#
# Calls the same OpenAI-compatible chat completions API configured for
# release.yml (repository secrets LLM/KEY/API). The system prompt is read
# from $LLM_SYSTEM_PROMPT, the user prompt is read from stdin, and the raw
# model answer is printed to stdout.
#
# Secret handling (must not change):
#   - Secrets are consumed ONLY via env vars (LLM_MODEL/LLM_KEY/LLM_API)
#     that callers set from `${{ secrets.* }}`. They are never echoed,
#     never written to disk, and never interpolated into the payload.
set -euo pipefail

LLM_MODEL="${LLM_MODEL:?LLM_MODEL env var is required}"
LLM_KEY="${LLM_KEY:?LLM_KEY env var is required}"
LLM_API="${LLM_API:?LLM_API env var is required}"

# DeepSeek serves /chat/completions at its base URL directly; other
# OpenAI-compatible platforms use <base>/v1/chat/completions.
if [[ "$LLM_API" == *"api.deepseek.com"* ]]; then
  ENDPOINT="$LLM_API/chat/completions"
else
  ENDPOINT="$LLM_API/v1/chat/completions"
fi

USER_INPUT="$(cat)"

# Build the payload with jq so prompts are passed as data, never evaluated
# by the shell. Temperature is kept low for deterministic review output.
payload=$(jq -n \
  --arg model "$LLM_MODEL" \
  --arg sys "${LLM_SYSTEM_PROMPT:-}" \
  --arg user "$USER_INPUT" \
  '{model: $model, messages: [
     {role: "system", content: $sys},
     {role: "user", content: $user}
   ], temperature: 0.3}')

curl -sS -f -m 240 -X POST \
  -H "Authorization: Bearer $LLM_KEY" \
  -H "Content-Type: application/json" \
  -d "$payload" "$ENDPOINT" \
  | jq -r '.choices[0].message.content // empty'
