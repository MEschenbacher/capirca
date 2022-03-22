"""Cumulus Linux iptables flavour."""

from capirca.lib import iptables
from string import Template
import io

_PLATFORM = 'cumulus'


class Term(iptables.Term):
  _PLATFORM = 'cumulus'
  _PREJUMP_FORMAT = None
  _TERM_FORMAT = None

  def _FormatPart(self, *args, **kwargs):
    if self.filter in ['INPUT', 'OUTPUT', 'FORWARD']:
      self._FILTER_TOP_FORMAT = Template('-A $filter')
    elif self.filter in ['PREROUTING', 'POSTROUTING']:
      self._FILTER_TOP_FORMAT = Template('-t mangle -A $filter')
    else:
      assert False
    return super()._FormatPart(*args, **kwargs)

class Cumulus(iptables.Iptables):
  _PLATFORM = 'cumulus'
  SUFFIX = '.cumulus'
  _TERM = Term
  # cumulus P{OST,RE}ROUTING do not support the default action
  _DEFAULTACTION_FORMAT = '# no default action for table %s %s'
  _GOOD_FILTERS = ['INPUT', 'OUTPUT', 'FORWARD', 'PREROUTING', 'POSTROUTING']

  def __init__(self, pol, exp_info):
    # we need to call __init__ once and safe exp_info
    super().__init__(pol, exp_info)
    self.pol = pol
    self.exp_info = exp_info


  def _set_af(self, af='inet6'):
    """
    af: inet6 or inet
    """
    for header, terms in self.pol.filters:
      if self._PLATFORM not in header.platforms:
        continue
      filter_options = header.FilterOptions(self._PLATFORM)
      if af == 'inet6':
        to_remove = 'inet'
      else:
        to_remove = 'inet6'
      if to_remove in filter_options:
          filter_options.remove(to_remove)
      if af not in filter_options:
        filter_options.append(af)

  def __str__(self):
    ret = io.StringIO()
    for af in ['inet6', 'inet']:
      self._set_af(af=af)
      # reset rules
      self.iptables_policies = []
      # XXX(meschenbacher) the policy is generated once on __init__ and the once again here
      self._TranslatePolicy(self.pol, self.exp_info)
      ret.write('[ip%stables]\n%s' % ('6' if af == 'inet6' else '', super().__str__()))
    return ret.getvalue()
