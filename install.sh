#!/usr/bin/env bash
set -euo pipefail

# Cerberus installer (development convenience)
# - Installs Python package with optional extras
# - Builds C core
# - Sets up Native Messaging for Firefox and Chrome (Linux)
#
# Options via env:
#  CERB_EXTRAS="ui-tui,ui-gui,automation-selenium"  (comma-separated)
#  CERB_SKIP_BUILD=1       # Skip cmake build
#  CERB_INSTALL_FF=1       # Install Firefox native host manifest
#  CERB_INSTALL_CHROME=1   # Install Chrome native host manifest
#  CERB_DATA_DIR=~/.cerberus

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
EXTRAS="${CERB_EXTRAS:-}"
VYPROJ="${ROOT_DIR}/pyproject.toml"
VENV_DIR="${ROOT_DIR}/.venv"
PIP_CMD="python3 -m pip"

info() { echo -e "\033[1;34m[cerberus]\033[0m $*"; }
warn() { echo -e "\033[1;33m[cerberus]\033[0m $*"; }
err()  { echo -e "\033[1;31m[cerberus]\033[0m $*"; }

install_playwright_browsers() {
  # If Playwright is installed in venv, install the browser binaries
  if [[ -x "${VENV_DIR}/bin/playwright" ]]; then
    info "Installing Playwright browsers (chromium, firefox, webkit)"
    "${VENV_DIR}/bin/playwright" install || warn "Playwright browser install failed; you can run '${VENV_DIR}/bin/playwright install' later"
  else
    warn "Playwright CLI not found in venv; skipping browser install"
  fi
}

install_deps() {
  # Install required system packages if a known package manager is available
  if command -v apt-get >/dev/null 2>&1; then
    info "Installing system dependencies with apt (may prompt for sudo password)"
    if command -v sudo >/dev/null 2>&1; then
      sudo apt-get update -y || true
      sudo apt-get install -y cmake build-essential libssl-dev python3-venv || true
    else
      apt-get update -y || true
      apt-get install -y cmake build-essential libssl-dev python3-venv || true
    fi
  elif command -v dnf >/dev/null 2>&1; then
    warn "dnf detected. Please install: sudo dnf install cmake gcc gcc-c++ openssl-devel python3-virtualenv"
  elif command -v yum >/dev/null 2>&1; then
    warn "yum detected. Please install: sudo yum install cmake gcc gcc-c++ openssl-devel python3-virtualenv"
  elif command -v pacman >/dev/null 2>&1; then
    warn "pacman detected. Please install: sudo pacman -S cmake base-devel openssl python-virtualenv"
  elif command -v brew >/dev/null 2>&1; then
    warn "Homebrew detected. Please install: brew install cmake openssl@3 && ensure Python venv module is available"
  else
    warn "Unknown package manager. Please install cmake, a C toolchain, OpenSSL dev headers, and python3-venv manually."
  fi
}

ensure_venv() {
  if [[ "${CERB_USE_VENV:-1}" == "1" ]]; then
    if [[ ! -d "${VENV_DIR}" ]]; then
      info "Creating virtual environment at ${VENV_DIR}"
      if ! python3 -m venv "${VENV_DIR}" 2>/dev/null; then
        err "Failed to create virtualenv. Please install python3-venv (e.g., sudo apt install python3.13-venv) and re-run."
        exit 1
      fi
    fi
    PIP_CMD="${VENV_DIR}/bin/pip"
  fi
}

pip_install() {
  local user_flag=""
  if [[ "${CERB_PIP_USER:-}" == "1" ]]; then
    user_flag="--user"
    warn "Using --user install (CERB_PIP_USER=1)"
  fi
  if [[ -n "${EXTRAS}" ]]; then
    info "Installing Python package with extras: ${EXTRAS}"
    ${PIP_CMD} install ${user_flag} -e ".[${EXTRAS}]"
  else
    info "Installing Python package (base)"
    ${PIP_CMD} install ${user_flag} -e .
  fi
}

build_c_core() {
  if [[ "${CERB_SKIP_BUILD:-}" == "1" ]]; then
    warn "Skipping C core build (CERB_SKIP_BUILD=1)"
    return
  fi
  info "Building C core with CMake"
  mkdir -p build
  (cd build && cmake .. && make -j)
  if command -v sudo >/dev/null 2>&1; then
    warn "Attempting 'make install' (may prompt for sudo password)"
    (cd build && sudo make install) || warn "'make install' failed; continuing"
  else
    warn "sudo not available; skipping 'make install'"
  fi
}

setup_native_firefox() {
  local host_bin host_manifest target
  local vhost="${VENV_DIR}/bin/cerberus-native-host"
  if [[ -x "${vhost}" ]]; then
    host_bin="${vhost}"
  else
    host_bin="$(command -v cerberus-native-host || true)"
  fi
  if [[ -z "${host_bin}" ]]; then
    err "cerberus-native-host not found on PATH; ensure pip install succeeded"
    return 1
  fi
  host_manifest="${ROOT_DIR}/native/manifests/firefox_com.cerberus.pm.json"
  target="$HOME/.mozilla/native-messaging-hosts/com.cerberus.pm.json"
  mkdir -p "$(dirname "${target}")"
  cp "${host_manifest}" "${target}"
  # Replace path in manifest
  sed -i "s#/usr/local/bin/cerberus-native-host#${host_bin//\//\\/}#" "${target}"
  info "Installed Firefox native host manifest at ${target}"
}

setup_native_chrome() {
  local host_bin target dir
  host_bin="$(command -v cerberus-native-host || true)"
  if [[ -z "${host_bin}" ]]; then
    err "cerberus-native-host not found on PATH; ensure pip install succeeded"
    return 1
  fi
  dir="$HOME/.config/google-chrome/NativeMessagingHosts"
  target="${dir}/com.cerberus.pm.json"
  mkdir -p "${dir}"
  cat > "${target}" <<EOF
{
  "name": "com.cerberus.pm",
  "description": "Cerberus Password Manager Native Messaging Host (dev)",
  "path": "${host_bin}",
  "type": "stdio",
  "allowed_origins": [
    "chrome-extension://REPLACE_WITH_EXTENSION_ID/"
  ]
}
EOF
  info "Installed Chrome native host manifest at ${target}"
  warn "Replace REPLACE_WITH_EXTENSION_ID with your unpacked extension ID in chrome://extensions"
}

main() {
  info "Starting Cerberus installation"
  install_deps
  ensure_venv
  pip_install
  install_playwright_browsers
  build_c_core

  if [[ "${CERB_INSTALL_FF:-}" == "1" ]]; then
    setup_native_firefox || true
  fi
  if [[ "${CERB_INSTALL_CHROME:-}" == "1" ]]; then
    setup_native_chrome || true
  fi

  info "Done. You can run: cerberus init, cerberus tui, cerberus gui"
}

main "$@"
