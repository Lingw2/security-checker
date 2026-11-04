#!/usr/bin/env bash
# スキャナ (gitleaks・trivy・osv-scanner・semgrep) を <インストール先> に入れる。Linux の amd64 / arm64 用。
#
#   scripts/install-scanners.sh <インストール先ディレクトリ>
#
# action.yml・自リポジトリの workflow・Dockerfile から呼ぶ。版と sha256 は scanner-versions.sh に固定してある。
#
# 環境変数で版を上書きできる (空なら固定版):
#   GITLEAKS_VERSION / TRIVY_VERSION / OSV_SCANNER_VERSION / SEMGREP_VERSION
#   値は X.Y.Z (先頭の v は可) か latest。latest は gh で最新リリースを引く (GH_TOKEN を使う)。
#
# 検証の強さは版によって変わり、それを隠さない:
#   - 固定版: ここに書いた sha256 で検証する (リリースごと差し替えられても止まる)
#   - それ以外: そのリリースのチェックサムファイルで検証し、警告を出す
#     (破損や途中の改ざんは止まるが、リリースごと差し替えられた場合は止まらない)
set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=scripts/scanner-versions.sh
source "$script_dir/scanner-versions.sh"

if [[ $# -ne 1 ]]; then
  echo "使い方: $0 <インストール先ディレクトリ>" >&2
  exit 2
fi
bin_dir=$1

# validate <名前> <指定>: 空・latest・X.Y.Z (先頭の v は可) 以外は止める。取得を始める前にすべて確かめる
validate() {
  if [[ -n "$2" && "$2" != latest && ! "${2#v}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "::error::$1 の版の指定が不正です: $2 (例 1.2.3 または latest。空なら固定版)" >&2
    exit 2
  fi
}
validate gitleaks "${GITLEAKS_VERSION:-}"
validate trivy "${TRIVY_VERSION:-}"
validate osv-scanner "${OSV_SCANNER_VERSION:-}"
validate semgrep "${SEMGREP_VERSION:-}"

if [[ "$(uname -s)" != Linux ]]; then
  # 取得するのは Linux 用のバイナリだけ. 別の OS では分かりにくい形で落ちるので取得を始める前に止める
  echo "::error::scripts/install-scanners.sh は Linux 専用です (現在: $(uname -s))。" \
    "macOS / Windows では各スキャナを手元のパッケージマネージャで入れてください" >&2
  exit 2
fi

case "$(uname -m)" in
  x86_64 | amd64) arch=amd64 ;;
  aarch64 | arm64) arch=arm64 ;;
  *)
    echo "::error::未対応のアーキテクチャです: $(uname -m)" >&2
    exit 1
    ;;
esac

mkdir -p "$bin_dir"
work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT

# resolve <owner/repo> <指定> <固定版>: 実際に入れる版 (先頭の v を除く)
resolve() {
  local requested=${2:-$3}
  if [[ "$requested" == latest ]]; then
    # gh は GitHub ホストのランナーに標準で入っている。curl の出力をインタプリタに流さない
    if ! command -v gh >/dev/null; then
      echo "::error::$1 に latest を指定するには gh が必要です" >&2
      exit 1
    fi
    requested=$(gh api "repos/$1/releases/latest" --jq .tag_name)
    validate "$1" "$requested"
  fi
  echo "${requested#v}"
}

# expected_sha256 <名前> <版> <固定版> <固定 sha256> <チェックサムファイルの URL> <ファイル名>
expected_sha256() {
  if [[ "$2" == "$3" ]]; then
    echo "$4"
    return
  fi
  echo "::warning::$1 $2 は固定版 ($3) ではないため、リリース側のチェックサムで検証します。リリースごと差し替えられた場合は検出できません" >&2
  local sha
  sha=$(curl -fsSL "$5" | awk -v f="$6" '$2 == f || $2 == "*" f { print $1 }')
  if [[ ! "$sha" =~ ^[0-9a-f]{64}$ ]]; then
    echo "::error::$1 $2 のチェックサムが見つかりません: $6" >&2
    exit 1
  fi
  echo "$sha"
}

# download <URL> <保存先> <sha256>: 取得し、sha256 が一致しなければ失敗する
download() {
  curl -fsSL -o "$2" "$1"
  echo "$3  $2" | sha256sum -c --quiet -
}

# --- gitleaks ---
ver=$(resolve gitleaks/gitleaks "${GITLEAKS_VERSION:-}" "$PINNED_GITLEAKS_VERSION")
case "$arch" in amd64) pinned_sha=$GITLEAKS_SHA256_AMD64 file_arch=x64 ;; arm64) pinned_sha=$GITLEAKS_SHA256_ARM64 file_arch=arm64 ;; esac
base="https://github.com/gitleaks/gitleaks/releases/download/v${ver}"
file="gitleaks_${ver}_linux_${file_arch}.tar.gz"
sha=$(expected_sha256 gitleaks "$ver" "$PINNED_GITLEAKS_VERSION" "$pinned_sha" "$base/gitleaks_${ver}_checksums.txt" "$file")
download "$base/$file" "$work_dir/gitleaks.tar.gz" "$sha"
tar xzf "$work_dir/gitleaks.tar.gz" -C "$work_dir" gitleaks
install -m 0755 "$work_dir/gitleaks" "$bin_dir/gitleaks"

# --- trivy ---
# 公式 install.sh の `curl | sh` は使わない。取得したスクリプトを検証せず実行することになるため
ver=$(resolve aquasecurity/trivy "${TRIVY_VERSION:-}" "$PINNED_TRIVY_VERSION")
case "$arch" in amd64) pinned_sha=$TRIVY_SHA256_AMD64 file_arch=64bit ;; arm64) pinned_sha=$TRIVY_SHA256_ARM64 file_arch=ARM64 ;; esac
base="https://github.com/aquasecurity/trivy/releases/download/v${ver}"
file="trivy_${ver}_Linux-${file_arch}.tar.gz"
sha=$(expected_sha256 trivy "$ver" "$PINNED_TRIVY_VERSION" "$pinned_sha" "$base/trivy_${ver}_checksums.txt" "$file")
download "$base/$file" "$work_dir/trivy.tar.gz" "$sha"
tar xzf "$work_dir/trivy.tar.gz" -C "$work_dir" trivy
install -m 0755 "$work_dir/trivy" "$bin_dir/trivy"

# --- osv-scanner ---
ver=$(resolve google/osv-scanner "${OSV_SCANNER_VERSION:-}" "$PINNED_OSV_SCANNER_VERSION")
case "$arch" in amd64) pinned_sha=$OSV_SCANNER_SHA256_AMD64 ;; arm64) pinned_sha=$OSV_SCANNER_SHA256_ARM64 ;; esac
base="https://github.com/google/osv-scanner/releases/download/v${ver}"
file="osv-scanner_linux_${arch}"
sha=$(expected_sha256 osv-scanner "$ver" "$PINNED_OSV_SCANNER_VERSION" "$pinned_sha" "$base/osv-scanner_SHA256SUMS" "$file")
download "$base/$file" "$work_dir/osv-scanner" "$sha"
install -m 0755 "$work_dir/osv-scanner" "$bin_dir/osv-scanner"

# --- semgrep (PyPI) ---
requested=${SEMGREP_VERSION:-$PINNED_SEMGREP_VERSION}
if [[ "$requested" == latest ]]; then
  spec=semgrep
else
  spec="semgrep==${requested#v}"
fi
# 固定版は推移的な依存まで版とハッシュで固定して入れる (semgrep-requirements.txt)。
# それ以外の版は依存を固定できないので、そのことを警告する
if [[ "$spec" == "semgrep==$PINNED_SEMGREP_VERSION" ]]; then
  requirements=(--require-hashes -r "$script_dir/semgrep-requirements.txt")
else
  echo "::warning::semgrep は固定版 ($PINNED_SEMGREP_VERSION) ではなく ${spec} を入れます (依存はハッシュで検証されません)" >&2
  requirements=("$spec")
fi
# 専用の venv に入れて <インストール先> にリンクする。本体と同じ環境に入れると依存の版がぶつかり、
# uv tool の bin は PATH に載っている保証が無い。uv が無い場合 (Docker イメージのビルド時) は venv + pip
venv_dir="$(dirname "$bin_dir")/semgrep-venv"
if command -v uv >/dev/null; then
  uv venv --quiet --allow-existing "$venv_dir"
  uv pip install --quiet --python "$venv_dir/bin/python" "${requirements[@]}"
else
  python3 -m venv "$venv_dir"
  "$venv_dir/bin/pip" install --no-cache-dir --quiet "${requirements[@]}"
fi
# semgrep は pysemgrep を PATH から起動するため、両方をリンクする
for name in semgrep pysemgrep; do
  if [[ -e "$venv_dir/bin/$name" ]]; then
    ln -sf "$venv_dir/bin/$name" "$bin_dir/$name"
  fi
done

# `| head` で切り詰めない。head が先にパイプを閉じると SIGPIPE になり、pipefail で失敗するため
"$bin_dir/gitleaks" version
"$bin_dir/trivy" --version
"$bin_dir/osv-scanner" --version
SEMGREP_ENABLE_VERSION_CHECK=0 "$bin_dir/semgrep" --version
