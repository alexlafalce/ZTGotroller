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
lifecycle for 1.14.2. It does not yet validate a current MPL agent or
peer-to-peer frame exchange between two members.
