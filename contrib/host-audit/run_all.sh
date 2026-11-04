#!/usr/bin/env bash
# 環境系セキュリティチェックを一括実行する。cron等での定期実行を想定。
# 使い方: ./run_all.sh [検査対象プロジェクトのパス] [--domain example.com]
set -uo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT=""
DOMAIN=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain)
      if [[ $# -lt 2 || -z "${2:-}" || "$2" == --* ]]; then
        echo "使い方: $0 [検査対象プロジェクトのパス] [--domain example.com]" >&2
        echo "❌ --domain にはドメイン名が必要です" >&2
        exit 2
      fi
      DOMAIN="$2"; shift 2 ;;
    *) PROJECT="$1"; shift ;;
  esac
done

total=0; failed=0; skipped=0
declare -a failures=() skips=()

run() { # 名前 コマンド...
  local name="$1"; shift
  total=$((total+1))
  echo ""
  echo "════════ $name ════════"
  "$@"
  local rc=$?
  if [[ $rc -eq 0 ]]; then
    :
  elif [[ $rc -eq 2 ]]; then
    # 検査できなかった (必要なコマンドが無いなど). 「通過」とも「要対応」とも数えない
    skipped=$((skipped+1))
    skips+=("$name")
  else
    failed=$((failed+1))
    failures+=("$name")
  fi
}

if [[ "$(uname)" == "Darwin" ]]; then
  run "macOS設定監査"        bash "$DIR/audit_macos.sh"
fi
run "開放ポート"           bash "$DIR/check_ports.sh"
run "ファイル権限"         bash "$DIR/check_permissions.sh" ${PROJECT:+"$PROJECT"}
run "シェル履歴/環境変数"  bash "$DIR/check_shell_env.sh"
if [[ "$(uname)" == "Darwin" ]]; then
  run "更新/バックアップ"    bash "$DIR/check_updates.sh"
fi
if [[ -n "$PROJECT" && -d "$PROJECT/.git" ]]; then
  run "git履歴の漏洩"      bash "$DIR/check_git_history.sh" "$PROJECT"
fi
if [[ -n "$DOMAIN" ]]; then
  run "TLS証明書"          bash "$DIR/check_tls_cert.sh" "$DOMAIN"
fi

echo ""
echo "══════════════ 総括 ══════════════"
echo "実行: ${total} 件 / 要対応: ${failed} 件 / 未実行: ${skipped} 件"
if [[ $skipped -gt 0 ]]; then
  for s in "${skips[@]}"; do echo "  ⚠️ $s (検査できませんでした)"; done
fi
if [[ $failed -gt 0 ]]; then
  for f in "${failures[@]}"; do echo "  ❌ $f"; done
  exit 1
fi
if [[ $skipped -gt 0 ]]; then
  echo "⚠️ 検査できなかったチェックがあります (通過とは扱いません)"
  exit 2
fi
echo "✅ すべてのチェックを通過しました"
