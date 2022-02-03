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

  def _TranslatePolicy(self, pol, exp_info):
    ret = super()._TranslatePolicy(pol, exp_info)
    if 'inet6' in self.filter_options:
      self.address_family = 'inet6'
    else:
      self.address_family = 'inet'
    return ret

  def __str__(self):
    if self.address_family == 'inet6':
      return '[ip6tables]\n%s' % super().__str__()
    else:
      return '[iptables]\n%s' % super().__str__()
