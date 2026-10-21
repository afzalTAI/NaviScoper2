#!/bin/sh
# Emergency cleanup: turn off system HTTP/HTTPS proxy routing on every network
# service. Use after a force-killed NaviScope (kill -9 or crash) that had
# "Route system traffic" enabled, or any time browsing breaks after quitting.
set -eu
services=$(networksetup -listallnetworkservices | tail -n +2)
for svc in $services; do
	case "$svc" in
	\**) continue ;;
	esac
	networksetup -setwebproxystate "$svc" off 2>/dev/null || true
	networksetup -setsecurewebproxystate "$svc" off 2>/dev/null || true
	echo "proxy off: $svc"
done
