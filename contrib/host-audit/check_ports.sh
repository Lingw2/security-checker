#!/usr/bin/env bash
# 待ち受け中のポートとプロセスを棚卸しし、外部公開されているものを警告する。
# 使い方: ./check_ports.sh
set -uo pipefail

# 終了コード: 0 = 外部公開なし / 1 = 要対応 / 2 = 検査できなかった (run_all.sh が区別する)

# LISTEN 中の TCP ソケットを「プロセス PID アドレス」の 1 行ずつにそろえる
if command -v lsof >/dev/null 2>&1; then
  listening=$(lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | tail -n +2 | awk '{print $1, $2, $9}')
elif command -v ss >/dev/null 2>&1; then
  # 例: LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=812,fd=3))
  listening=$(ss -ltnpH 2>/dev/null | awk '{
    cmd = "?"; pid = "?"
    if (match($0, /users:\(\("[^"]+",pid=[0-9]+/)) {
      split(substr($0, RSTART, RLENGTH), parts, /[",=]+/); cmd = parts[2]; pid = parts[4]
    }
    print cmd, pid, $4
  }')
else
  echo "⚠️ lsof も ss も無いため、ポートを検査できませんでした (未実行)"
  exit 2
fi

echo "=== 開いているポートの棚卸し ==="
echo ""

if [[ -z "$listening" ]]; then
  echo "待ち受け中のポートはありません"
  exit 0
fi

printf "%-20s %-8s %-25s %s\n" "プロセス" "PID" "待ち受けアドレス" "公開範囲"
echo "--------------------------------------------------------------------------"

external=0
while IFS= read -r line; do
  read -r cmd pid addr <<< "$line"
  case "$addr" in
    127.*:*|\[::1\]:*|\[::ffff:127.*\]:*|localhost:*)
      scope="ローカルのみ" ;;
    \*:*|0.0.0.0:*|\[::\]:*|\[::\]%*:*)
      scope="⚠️ 全インターフェース(外部から到達可能な可能性)"
      external=$((external+1)) ;;
    *)
      scope="特定アドレス" ;;
  esac
  printf "%-20s %-8s %-25s %s\n" "$cmd" "$pid" "$addr" "$scope"
done <<< "$listening"

echo ""
if [[ $external -gt 0 ]]; then
  echo "⚠️ 全インターフェースで待ち受け中のポートが ${external} 件あります。"
  echo "   開発サーバー等は 127.0.0.1 にバインドするか、不要なら停止してください。"
  echo "   (macOSのファイアウォールやルーターのNAT内なら直ちに危険とは限りません)"
  exit 1
else
  echo "✅ 外部に公開されているポートはありません(すべてローカル待ち受け)"
fi
