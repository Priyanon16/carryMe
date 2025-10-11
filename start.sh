#!/usr/bin/env bash
set -e

echo "== write rclone.conf =="
cat > /app/rclone.conf <<EOF
[supabase]
type = s3
provider = Other
env_auth = false
access_key_id = ${SB_S3_KEY}
secret_access_key = ${SB_S3_SECRET}
endpoint = https://${SB_PROJECT_REF}.supabase.co/storage/v1/s3
no_check_bucket = true
EOF

mkdir -p /app/wwwroot/uploads

echo "== ensure remote folders =="
rclone mkdir supabase:${SB_BUCKET} --config /app/rclone.conf || true
rclone mkdir supabase:${SB_BUCKET}/uploads --config /app/rclone.conf || true

echo "== restore (if any) =="
rclone copy -v supabase:${SB_BUCKET}/carryme.db /app --config /app/rclone.conf || true
rclone copy -v supabase:${SB_BUCKET}/uploads /app/wwwroot/uploads --config /app/rclone.conf || true

[ -f /app/carryme.db ] && echo "DB restored OK" || echo "DB not found on remote (first run?)"

echo "== start app =="
set +e
dotnet carryMe.dll &
APP_PID=$!
set -e

echo "== seed backup immediately =="
[ -f /app/carryme.db ] && rclone copy -v /app/carryme.db supabase:${SB_BUCKET} --config /app/rclone.conf || true
rclone copy -v /app/wwwroot/uploads supabase:${SB_BUCKET}/uploads --config /app/rclone.conf || true

echo "== backup loop (every 10s) =="
while sleep 10; do
  [ -f /app/carryme.db ] && rclone copy -v /app/carryme.db supabase:${SB_BUCKET} --config /app/rclone.conf || true
  rclone copy -v /app/wwwroot/uploads supabase:${SB_BUCKET}/uploads --config /app/rclone.conf || true
done
