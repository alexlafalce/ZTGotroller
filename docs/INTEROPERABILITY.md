# Interoperability validation

## ZeroTier One 1.14.2

Validated on July 28, 2026 against the unmodified `zerotier-one` binary built
from commit `185a3a2c76e6bf1b1c0415871f43076638eb007c`.

The isolated lab used a temporary private planet, a configurable upstream HELLO
announcement, a direct physical path hint, and the ZTGotroller administrative
API. The observed lifecycle was:

1. The agent learned the controller identity by WHOIS from the private planet.
2. The agent established an authenticated direct path to the Go controller.
3. A compressed, AES-armored configuration request registered the member.
4. The private network initially reported `ACCESS_DENIED`.
5. After assigning `10.99.0.2`, adding route `10.99.0.0/24`, and authorizing
   the member, the unmodified agent reported network status `OK`.
6. The agent reported the expected network name, broadcast setting, route, MTU,
   and managed address `10.99.0.2/24`.

This validates controller discovery and the control-plane configuration
lifecycle for 1.14.2.

## Current MPL agent

Validated on July 28, 2026 against the unmodified `zerotier-one` binary built
from ZeroTierOne `origin/dev` commit
`899352e38405968516bb12a770f0ac02f6058fa8` (reported version `1.16.2`).

The current agent used the same isolated private planet and joined the same
network as the 1.14.2 agent. After authorization it reported status `OK`,
route `10.99.0.0/24`, and managed address `10.99.0.3/24`.

Peer-to-peer ICMP from the current MPL member (`10.99.0.3`) to the 1.14.2
member (`10.99.0.2`) completed 3 of 3 probes with zero packet loss. This closes
the initial interoperability milestone for controller discovery, mixed-version
configuration, and peer data-plane establishment.
