"""Cumulus Linux iptables flavour."""

from capirca.lib import iptables
from string import Template
import io

_PLATFORM = 'cumulus'


class Term(iptables.Term):
  _PLATFORM = 'cumulus'
  _PREJUMP_FORMAT = None
  _TERM_FORMAT = None
  _FILTER_TOP_FORMAT = Template('-A $filter')


class Cumulus(iptables.Iptables):
  _PLATFORM = 'cumulus'
  SUFFIX = '.ipt-cumulus'
  _TERM = Term

  def __init__(self, pol, exp_info):
    # call once
    super().__init__(pol, exp_info)
    self.pol = pol
    self.exp_info = exp_info


  def _add_af_to_filter(self, af='inet6'):
    """
    af: inet6 or inet
    """
    for header, terms in self.pol.filters:
      if self._PLATFORM not in header.platforms:
        continue
      filter_options = header.FilterOptions(self._PLATFORM)
      if af not in filter_options:
        filter_options.append(af)

  def _remove_af_from_filter(self, af='inet6'):
    """
    af: inet6 or inet
    """
    for header, terms in self.pol.filters:
      if self._PLATFORM not in header.platforms:
        continue
      filter_options = header.FilterOptions(self._PLATFORM)
      if af in filter_options:
        filter_options.remove(af)

  def __str__(self):
    ret = io.StringIO()
    for af in ['inet6', 'inet']:
      self._add_af_to_filter(af=af)
      # reset rules
      self.iptables_policies = []
      self._TranslatePolicy(self.pol, self.exp_info)
      ret.write('[ip%stables]\n%s' % ('6' if af == 'inet6' else '', super().__str__()))
      self._remove_af_from_filter(af=af)
    return ret.getvalue()
