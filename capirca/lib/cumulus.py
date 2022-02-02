"""Cumulus Linux iptables flavour."""

from capirca.lib import iptables

_PLATFORM = 'cumulus'


class Term(iptables.Term):
    _PLATFORM = 'cumulus'


class Cumulus(iptables.Iptables):
    _PLATFORM = 'cumulus'
    SUFFIX = '.ipt-cumulus'
