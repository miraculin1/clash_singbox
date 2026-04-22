#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  sync_remote.sh --host HOST --user USER [--port 22] [--local-file ./out.json] [--remote-path /etc/sing-box/config.json]

Options:
  --host         Remote host or IP (required)
  --user         Remote SSH user (required)
  --port         Remote SSH port (default: 22)
  --local-file   Local config file to upload (default: ./out.json)
  --remote-path  Remote destination path (default: /etc/sing-box/config.json)
  -h, --help     Show this help message
EOF
}

HOST=""
USER_NAME=""
PORT="22"
LOCAL_FILE="./out.json"
REMOTE_PATH="/etc/sing-box/config.json"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host)
      HOST="${2:-}"
      shift 2
      ;;
    --user)
      USER_NAME="${2:-}"
      shift 2
      ;;
    --port)
      PORT="${2:-}"
      shift 2
      ;;
    --local-file)
      LOCAL_FILE="${2:-}"
      shift 2
      ;;
    --remote-path)
      REMOTE_PATH="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ -z "$HOST" || -z "$USER_NAME" ]]; then
  echo "--host and --user are required." >&2
  usage
  exit 1
fi

if [[ ! -f "$LOCAL_FILE" ]]; then
  echo "Local file not found: $LOCAL_FILE" >&2
  exit 1
fi

if ! [[ "$PORT" =~ ^[0-9]+$ ]]; then
  echo "Invalid --port value: $PORT" >&2
  exit 1
fi

if ! command -v ssh >/dev/null 2>&1; then
  echo "ssh command not found." >&2
  exit 1
fi

if ! command -v scp >/dev/null 2>&1; then
  echo "scp command not found." >&2
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 command not found." >&2
  exit 1
fi

echo "Validating local JSON file: $LOCAL_FILE"
python3 -c 'import json,sys; json.load(open(sys.argv[1], "r", encoding="utf-8"))' "$LOCAL_FILE"

TARGET="${USER_NAME}@${HOST}"
REMOTE_TMP="/tmp/sing-box.config.new"
SSH_COMMON_ARGS=(-p "$PORT")
SCP_COMMON_ARGS=(-P "$PORT")

echo "Uploading file to remote temp path: $REMOTE_TMP"
scp "${SCP_COMMON_ARGS[@]}" "$LOCAL_FILE" "${TARGET}:${REMOTE_TMP}"

read -r -s -p "Enter sudo password for ${USER_NAME}@${HOST}: " SUDO_PASSWORD
echo

echo "Running remote validate/deploy/restart sequence..."
printf '%s\n' "$SUDO_PASSWORD" | ssh "${SSH_COMMON_ARGS[@]}" "$TARGET" \
  "set -euo pipefail
read -r SUDO_PASSWORD
cleanup() { rm -f '$REMOTE_TMP'; }
trap cleanup EXIT

printf '%s\n' \"\$SUDO_PASSWORD\" | sudo -S -p '' -v >/dev/null
sing-box check -c '$REMOTE_TMP'
printf '%s\n' \"\$SUDO_PASSWORD\" | sudo -S -p '' cp '$REMOTE_TMP' '$REMOTE_PATH'
printf '%s\n' \"\$SUDO_PASSWORD\" | sudo -S -p '' systemctl restart sing-box
printf '%s\n' \"\$SUDO_PASSWORD\" | sudo -S -p '' systemctl is-active --quiet sing-box
"

unset SUDO_PASSWORD
echo "Deployment completed: ${HOST}:${REMOTE_PATH}"
