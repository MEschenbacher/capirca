# cumulus

The cumulus generator builds on top of the iptables generator and produces output for Mellanox
ASIC (Spectrum 1 and greater) with a reduced feature set (e.g. without creating custom chains
for each command, no state support for forwarding) that must be placed into a file in the
Cumulus Linux ACL directory (/etc/cumulus/policy), ending in `*.rules` and applied using
`cl-acltool -i`.

Differences to iptables and in Mellanox hardware:

- only chains _INPUT_ (filter), _OUTPUT_ (filter), _FORWARD_ (filter), _POSTROUTING_ (mangle),
  _PREROUTING_ (mangle) are supported. The Nvidia documentation for cumulus ACL is not very
  exact on when to use _FORWARD_, _POSTROUTING_, _PREROUTING_ as it [currently only
  states](https://docs.nvidia.com/networking-ethernet-software/cumulus-linux-510/System-Configuration/Access-Control-Lists/Access-Control-List-Configuration/)
  "Cumulus Linux 5.0 and later uses the `-t mangle -A PREROUTING` chain for ingress rules and
  the -t mangle -A POSTROUTING chain for egress rules instead of the `-A FORWARD` chain used
  in previous releases.", which seems to imply that only *FORWARD* is to be used. However,
  there seem to be valid use cases for all three chains. We've found that there is currently
  no way to match egress traffic in *FORWARD* without specifying a out-interface. For this
  case, we would need to use *POSTROUTING*, however VXLAN gets encapsulated *before* the
  *POSTROUTING* and might not be available for matching.
- _POSTROUTING_ and _PREROUTING_ automatically generate in the `-t mangle` table (as per
  Nvidia documentation)
- stateful filtering (conntrack) is not supported for _FORWARD_, _POSTROUTING_, _PREROUTING_
  and _nostate_ **must** be specified
- filter options _inet6_ and _inet_ **must not** be specified (the generated ruleset always
  contains both address families)

The remaining sections highlight *differences* to the [iptables
generator](doc/generators/iptables.md).

## header format

The cumulus header designation has the following format:
```
target:: cumulus [INPUT|OUTPUT|FORWARD|PREROUTING|POSTROUTING] {ACCEPT|DROP} {truncatenames} {nostate}
```
  * _nostate_: **must always** be specified to produce 'stateless' filter output (e.g. no connection tracking)_
  * although a default action *{ACCEPT|DROP}* can be specified, this has no effect and no
    action will be executed
