#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Copyright (C) 2026 bilieebiliee1-design
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#
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

# Endpoint policy. Callers (the workflows) pre-compute the chat
# completions URL via LLM_ENDPOINT and a User-Agent value via
# LLM_USER_AGENT; those win when provided. When LLM_ENDPOINT is empty the
# built-in detection is used: Tencent Copilot
# (https://copilot.tencent.com) serves /v2/chat/completions and needs a
# User-Agent header; DeepSeek serves /chat/completions at its base URL
# directly; other OpenAI-compatible platforms use <base>/v1/chat/completions.
CURL_EXTRA_ARGS=()
if [ -n "${LLM_ENDPOINT:-}" ]; then
  ENDPOINT="$LLM_ENDPOINT"
  if [ -n "${LLM_USER_AGENT:-}" ]; then
    CURL_EXTRA_ARGS+=(-H "User-Agent: ${LLM_USER_AGENT}")
  fi
else
  if [[ "$LLM_API" == "https://copilot.tencent.com" ]]; then
    ENDPOINT="$LLM_API/v2/chat/completions"
    if [ -n "${USER_AGENT:-}" ]; then
      CURL_EXTRA_ARGS+=(-H "User-Agent: ${USER_AGENT}")
    fi
  elif [[ "$LLM_API" == *"api.deepseek.com"* ]]; then
    ENDPOINT="$LLM_API/chat/completions"
  else
    ENDPOINT="$LLM_API/v1/chat/completions"
  fi
fi

USER_INPUT="$(cat)"

# The user prompt carries the whole repository code context, which can exceed
# Linux's per-argument limit (MAX_ARG_STRLEN = 128KB). Passing it (and a large
# system prompt) to jq via `--arg` used to blow the argv limit and fail with
# "Argument list too long" (E2BIG), silently skipping the auto-reply. So we
# write both prompts to temp files and read them back with jq --rawfile, and
# hand curl the payload via `-d @file` — no large string ever travels through
# argv. Temperature is kept low for deterministic review output.
sys_file="$(mktemp)"
user_file="$(mktemp)"
payload_file="$(mktemp)"
body_file="$(mktemp)"
http_file="$(mktemp)"
trap 'rm -f "$sys_file" "$user_file" "$payload_file" "$body_file" "$http_file"' EXIT
printf '%s' "${LLM_SYSTEM_PROMPT:-}" > "$sys_file"
printf '%s' "$USER_INPUT" > "$user_file"

jq -n \
  --arg model "$LLM_MODEL" \
  --rawfile sys "$sys_file" \
  --rawfile user "$user_file" \
  '{model: $model, messages: [
     {role: "system", content: $sys},
     {role: "user", content: $user}
   ], temperature: 0.3}' > "$payload_file"

# M6: call the LLM API with a per-attempt timeout (240s) and retry with
# exponential backoff on transient failures (network/transport errors, HTTP 429,
# 5xx). Without this, an upstream hang would pin the job until its default
# 360-minute timeout. Non-retryable errors exit non-zero so callers fall back.
attempt=0
max_attempts=4
backoff=5
while [ "$attempt" -lt "$max_attempts" ]; do
  attempt=$((attempt + 1))
  if curl -sS --max-time 240 -w '%{http_code}' -o "$body_file" -X POST \
      -H "Authorization: Bearer $LLM_KEY" \
      -H "Content-Type: application/json" \
      "${CURL_EXTRA_ARGS[@]}" \
      -d "@$payload_file" "$ENDPOINT" > "$http_file" 2>/dev/null; then
    http_code=$(cat "$http_file")
  else
    http_code="000"
  fi
  if [ -z "$http_code" ] || [ "$http_code" = "000" ]; then
    # Transport error (connection refused, DNS, timeout, TLS, ...)
    if [ "$attempt" -ge "$max_attempts" ]; then
      echo "::error::LLM API unreachable after $max_attempts attempts" >&2
      exit 22
    fi
    echo "::warning::LLM API transport error (attempt $attempt/$max_attempts); retrying in ${backoff}s" >&2
    sleep "$backoff"; backoff=$((backoff * 2)); continue
  fi
  if [ "$http_code" -ge 200 ] && [ "$http_code" -lt 300 ]; then
    # Success: extract the model answer.
    jq -r '.choices[0].message.content // empty' "$body_file"
    exit 0
  fi
  # HTTP 429 (rate limited) and 5xx (server error) are retryable.
  if { [ "$http_code" -eq 429 ] || [ "$http_code" -ge 500 ]; } && [ "$attempt" -lt "$max_attempts" ]; then
    echo "::warning::LLM API returned HTTP $http_code (attempt $attempt/$max_attempts); retrying in ${backoff}s" >&2
    sleep "$backoff"; backoff=$((backoff * 2)); continue
  fi
  echo "::error::LLM API returned HTTP $http_code" >&2
  exit 22
done
exit 22
