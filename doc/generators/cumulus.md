# cumulus

The cumulus generator builds on top of the iptables generator and produces output with a
reduced feature set (without creating custom chains for each command) that must be placed into
a file in the Cumulus Linux ACL directory (/etc/cumulus/policy), ending in `*.rules` and
applies using `cl-acltool -i`.

Differences to iptables:
- only chains _INPUT_, _OUTPUT_, _FORWARD_ are supported
- stateful (conntrack) filtering is not supported, _nostate_ **must always be specified**
- filter options _inet6_ and _inet_ must not be specified (the generated ruleset always
  contains both address families)

The remaining sections highlight *differences* to the [iptables
generator](doc/generators/iptables.md).

## header format

The cumulus header designation has the following format:
```
target:: cumulus [INPUT|OUTPUT|FORWARD] {ACCEPT|DROP} {truncatenames} {nostate}
```
  * _nostate_: **must always be specified** specifies to produce 'stateless' filter output (e.g. no connection tracking)_
