#!/bin/sh
# The redirect that makes interception transparent: in the network namespace a
# workload shares with the AgentSafe interceptor (a pod, or containers joined
# with `network_mode: service:...`), every TCP connection the workload opens to
# port 80 or 443 is redirected to the interceptor's listeners on loopback,
# except what the interceptor itself sends, which is told apart by its user id.
# The workload changes nothing: its request leaves for the address it named
# and arrives at the interceptor, which reads the destination from the bytes.
#
# This runs once, as root with CAP_NET_ADMIN, in an init container built from
# the `init` stage of packages/agentsafe/Dockerfile, and exits. It is
# idempotent: run twice, it leaves one copy of every rule. It takes its
# settings from the environment and refuses a value that is not what it says
# it is, so nothing here is ever interpolated into a rule unchecked.
#
#   AGENTSAFE_INTERCEPT_UID            the interceptor's user id; its traffic is not redirected (65532)
#   AGENTSAFE_INTERCEPT_HTTP_PORT      where redirected port-80 connections go (15001)
#   AGENTSAFE_INTERCEPT_HTTPS_PORT     where redirected port-443 connections go (15002)
#   AGENTSAFE_INTERCEPT_HTTP_FROM      the plaintext port intercepted (80)
#   AGENTSAFE_INTERCEPT_HTTPS_FROM     the TLS port intercepted (443)
#   AGENTSAFE_INTERCEPT_EXCLUDE_CIDRS  destinations left alone, comma-separated (none)
#   AGENTSAFE_INTERCEPT_IPV6           auto | on | off: refuse IPv6 on the intercepted ports (auto)
#
# IPv6: the interceptor listens on 127.0.0.1, so an IPv6 connection to an
# intercepted port cannot be redirected to it yet. Rather than let it pass
# beside the boundary, it is refused with a reset when ip6tables is present
# (`auto`), required (`on`), or left alone (`off`, which a workload that must
# reach a destination over IPv6 sets knowingly).
set -eu

uid="${AGENTSAFE_INTERCEPT_UID:-65532}"
http_port="${AGENTSAFE_INTERCEPT_HTTP_PORT:-15001}"
https_port="${AGENTSAFE_INTERCEPT_HTTPS_PORT:-15002}"
http_from="${AGENTSAFE_INTERCEPT_HTTP_FROM:-80}"
https_from="${AGENTSAFE_INTERCEPT_HTTPS_FROM:-443}"
excludes="${AGENTSAFE_INTERCEPT_EXCLUDE_CIDRS:-}"
ipv6="${AGENTSAFE_INTERCEPT_IPV6:-auto}"

fail() {
  echo "agentsafe-redirect: $*" >&2
  exit 1
}

is_number() {
  case "$1" in
    ''|*[!0-9]*) return 1 ;;
    *) return 0 ;;
  esac
}

is_port() {
  is_number "$1" && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}

is_cidr() {
  case "$1" in
    ''|*[!0-9a-fA-F.:/]*) return 1 ;;
    *) return 0 ;;
  esac
}

is_number "$uid" || fail "AGENTSAFE_INTERCEPT_UID must be a user id"
is_port "$http_port" || fail "AGENTSAFE_INTERCEPT_HTTP_PORT must be a port"
is_port "$https_port" || fail "AGENTSAFE_INTERCEPT_HTTPS_PORT must be a port"
is_port "$http_from" || fail "AGENTSAFE_INTERCEPT_HTTP_FROM must be a port"
is_port "$https_from" || fail "AGENTSAFE_INTERCEPT_HTTPS_FROM must be a port"
[ "$http_port" != "$https_port" ] || fail "the two listener ports must differ"
case "$ipv6" in auto|on|off) ;; *) fail "AGENTSAFE_INTERCEPT_IPV6 must be auto, on or off" ;; esac
old_ifs="$IFS"
IFS=','
for cidr in $excludes; do
  is_cidr "$cidr" || fail "AGENTSAFE_INTERCEPT_EXCLUDE_CIDRS holds something that is not an address or a range"
done
IFS="$old_ifs"

command -v iptables >/dev/null 2>&1 || fail "iptables is not installed"

# A chain of our own for the redirect and one for the decision, so the rules
# are recognisable, replaceable, and never mixed with anyone else's.
ensure_chain() {
  iptables -t nat -N "$1" 2>/dev/null || true
  iptables -t nat -F "$1"
}

ensure_chain AGENTSAFE_REDIRECT
iptables -t nat -A AGENTSAFE_REDIRECT -p tcp --dport "$http_from" -j REDIRECT --to-ports "$http_port"
iptables -t nat -A AGENTSAFE_REDIRECT -p tcp --dport "$https_from" -j REDIRECT --to-ports "$https_port"

ensure_chain AGENTSAFE_OUTPUT
# The interceptor's own connections, to the destinations and to the authority,
# must not come back to it.
iptables -t nat -A AGENTSAFE_OUTPUT -m owner --uid-owner "$uid" -j RETURN
# Loopback stays local: a workload talking to a sidecar or to itself is not
# talking to a system of record.
iptables -t nat -A AGENTSAFE_OUTPUT -o lo -j RETURN
IFS=','
for cidr in $excludes; do
  iptables -t nat -A AGENTSAFE_OUTPUT -d "$cidr" -j RETURN
done
IFS="$old_ifs"
iptables -t nat -A AGENTSAFE_OUTPUT -j AGENTSAFE_REDIRECT

# One jump from OUTPUT, however many times this runs.
iptables -t nat -C OUTPUT -p tcp -j AGENTSAFE_OUTPUT 2>/dev/null \
  || iptables -t nat -A OUTPUT -p tcp -j AGENTSAFE_OUTPUT

if [ "$ipv6" != "off" ]; then
  if command -v ip6tables >/dev/null 2>&1 && [ -e /proc/net/if_inet6 ]; then
    ip6tables -N AGENTSAFE_OUTPUT6 2>/dev/null || true
    ip6tables -F AGENTSAFE_OUTPUT6
    ip6tables -A AGENTSAFE_OUTPUT6 -m owner --uid-owner "$uid" -j RETURN
    ip6tables -A AGENTSAFE_OUTPUT6 -o lo -j RETURN
    ip6tables -A AGENTSAFE_OUTPUT6 -p tcp --dport "$http_from" -j REJECT --reject-with tcp-reset
    ip6tables -A AGENTSAFE_OUTPUT6 -p tcp --dport "$https_from" -j REJECT --reject-with tcp-reset
    ip6tables -C OUTPUT -p tcp -j AGENTSAFE_OUTPUT6 2>/dev/null \
      || ip6tables -A OUTPUT -p tcp -j AGENTSAFE_OUTPUT6
  elif [ "$ipv6" = "on" ]; then
    fail "AGENTSAFE_INTERCEPT_IPV6=on but ip6tables or IPv6 is not available"
  else
    echo "agentsafe-redirect: IPv6 not available here; nothing to refuse"
  fi
fi

echo "agentsafe-redirect: outbound TCP :$http_from -> 127.0.0.1:$http_port and :$https_from -> 127.0.0.1:$https_port, except uid $uid and loopback"
iptables -t nat -S AGENTSAFE_OUTPUT
iptables -t nat -S AGENTSAFE_REDIRECT
