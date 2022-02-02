"""Cumulus Linux iptables flavour."""

from capirca.lib import iptables

_PLATFORM = 'cumulus'


class Term(iptables.Term):
    _PLATFORM = 'cumulus'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


class Cumulus(iptables.Iptables):
    SUFFIX = '.ipt-cumulus'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
