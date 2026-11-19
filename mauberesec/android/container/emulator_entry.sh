#!/bin/sh
# Emulator entry script (v0.9) — runs INSIDE the disposable emulator container.
#
# Fixed, argument-driven workflow. All adb calls target the emulator inside
# THIS container (localhost:5555); the host's adb and any personal device are
# never used. Emits a single JSON line on stdout.
#
# argv: 1=apk path 2=package 3=dataset dir 4=logcat seconds 5=run id
set -eu

APK_PATH="$1"
PACKAGE="$2"
DATASET_DIR="$3"
LOGCAT_SECONDS="$4"
RUN_ID="$5"

json_escape() {
  # minimal escaping for our controlled values
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g' | tr '\n' ' '
}

emit_json() {
  printf '{"run_id":"%s","apk_installed":%s,"launched":%s,"adb_endpoint":"%s",' \
    "$(json_escape "$RUN_ID")" "$1" "$2" "$(json_escape "${ADB_ENDPOINT:-emulator-5554}")"
}

fail() {
  printf '{"run_id":"%s","error":"%s"}\n' "$(json_escape "$RUN_ID")" "$(json_escape "$1")"
  exit 1
}

command -v adb >/dev/null 2>&1 || fail "adb not available in the emulator image"

# 1. Wait for the disposable emulator to be ready.
adb wait-for-device || fail "emulator device never became ready"
printf 'waiting for boot completion\n' >&2
_waited=0
while [ "$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" != "1" ]; do
  _waited=$((_waited + 1))
  [ "$_waited" -gt 120 ] && fail "emulator boot timeout"
  sleep 2
done

# 2. Synthetic dataset only.
if [ -d "$DATASET_DIR" ]; then
  adb push "$DATASET_DIR" /sdcard/Download/msai-synthetic >/dev/null 2>&1 \
    || fail "could not push synthetic dataset"
fi

# 3. Install (never on a personal device: this endpoint is the container's emulator).
INSTALL_OUT="$(adb install -r "$APK_PATH" 2>&1)" || fail "install failed: $INSTALL_OUT"
case "$INSTALL_OUT" in
  *Success*) APK_INSTALLED=true ;;
  *) fail "install did not report Success: $INSTALL_OUT" ;;
esac

# 4. Launch the app under the synthetic profile.
adb shell monkey -p "$PACKAGE" -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1 \
  || fail "could not launch package"
LAUNCHED=true

# 5. Capture runtime observations.
LOGCAT="$(timeout "$LOGCAT_SECONDS" adb logcat -d 2>/dev/null | tail -n 200 || true)"
PS_OUT="$(adb shell ps 2>/dev/null | head -n 50 || true)"
PKGS="$(adb shell pm list packages 2>/dev/null | grep -c . || echo 0)"

emit_json "$APK_INSTALLED" "$LAUNCHED"
printf '"package":"%s","packages_visible":%s,"process_count":%s,' \
  "$(json_escape "$PACKAGE")" "$PKGS" "$(printf '%s' "$PS_OUT" | grep -c . || echo 0)"
printf '"logcat_lines":%s,"logcat_tail":"%s","dataset_marker_seen":%s}\n' \
  "$(printf '%s' "$LOGCAT" | grep -c . || echo 0)" \
  "$(json_escape "$(printf '%s' "$LOGCAT" | tail -n 20)")" \
  "$(printf '%s' "$LOGCAT" | grep -q 'MSAI-SYNTHETIC-DATASET' && echo true || echo false)"
