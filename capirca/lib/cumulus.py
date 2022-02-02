"""Cumulus Linux iptables flavour."""

from capirca.lib import iptables
from string import Template

_PLATFORM = 'cumulus'


class Term(iptables.Term):
  _PLATFORM = 'cumulus'
  _PREJUMP_FORMAT = None
  _TERM_FORMAT = None
  _FILTER_TOP_FORMAT = Template('-A $filter')

  def __init__(self, term, filter_name, trackstate, filter_action, af='inet',
               verbose=True):
    # do not track state, regardless of what is configured
    super().__init__(term, filter_name, False, filter_action, af, verbose)


class Cumulus(iptables.Iptables):
  _PLATFORM = 'cumulus'
  SUFFIX = '.ipt-cumulus'
  _TERM = Term
