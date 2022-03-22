# Copyright 2017 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""NVUE selective vrf route leaking generator."""

from capirca.lib import aclgenerator
from capirca.lib.nacaddr import IPv4, IPv6

_PLATFORM = 'nvue-selective-vrf-route-leaking'


class Term(aclgenerator.Term):
    """A single vrf leaking term, mostly used for the __str__() method.

    Args:
        term: policy.Term object.
        filter_type: IP address version number.
    """
    def _BuildTokens(self):
        supported_tokens, supported_sub_tokens = super()._BuildTokens()
        #  supported_sub_tokens.update({'option': {'source-vrf', 'destination-vrf'}})
        return supported_tokens, supported_sub_tokens

    def __init__(self, term):
        super().__init__(term)
        self.term = term
        if len(self.term.option) % 2 != 0:
            raise Exception("Options have an uneven number of arguments")
        i = 0
        while i < len(self.term.option):
            if self.term.option[i] == 'source-vrf':
                self.term.source_vrf = self.term.option[i + 1]
                i += 2
            elif self.term.option[i] == 'destination-vrf':
                self.term.destination_vrf = self.term.option[i + 1]
                i += 2
            else:
                assert False

    def __str__(self):
        ret_str = []

        if not self.term.source_vrf or not self.term.destination_vrf:
            return ''

        common = "router policy prefix-list PL{{}}{}to{}".format(self.term.source_vrf, self.term.destination_vrf)
        ret_str.append("unset {}".format(common.format(4)))
        ret_str.append("set {} type ipv4".format(common.format(4)))
        ret_str.append("unset {}".format(common.format(6)))
        ret_str.append("set {} type ipv6".format(common.format(6)))
        i = 1
        for address in self.term.destination_address:
            if isinstance(address, IPv4):
                inet = 4
            elif isinstance(address, IPv6):
                inet = 6
            else:
                assert False
            ret_str.append("set {} rule {} match {}".format(common.format(inet), i, address))
            ret_str.append("set {} rule {} action permit".format(common.format(inet), i))
            i += 1

# this currently fails (see cumulus role and mellanox case)
        ret_str.append("set router policy route-map {0}to{1} rule 10 match ip-prefix-list PL6{0}to{1}".format(self.term.source_vrf, self.term.destination_vrf))
        ret_str.append("set router policy route-map {0}to{1} rule 10 action accept".format(self.term.source_vrf, self.term.destination_vrf))
        ret_str.append("set router policy route-map {0}to{1} rule 20 match ip-prefix-list PL4{0}to{1}".format(self.term.source_vrf, self.term.destination_vrf))
        ret_str.append("set router policy route-map {0}to{1} rule 20 action accept".format(self.term.source_vrf, self.term.destination_vrf))
        ret_str.append("set router policy route-map {0}to{1} rule 30 action deny".format(self.term.source_vrf, self.term.destination_vrf))
        ret_str.append("set vrf {} router bgp address-family ipv4-unicast route-import from-vrf list {}".format(self.term.source_vrf, self.term.destination_vrf))
        ret_str.append("set vrf {} router bgp address-family ipv6-unicast route-import from-vrf list {}".format(self.term.source_vrf, self.term.destination_vrf))
        ret_str.append("set vrf {1} router bgp address-family ipv4-unicast route-import from-vrf list {0}".format(self.term.source_vrf, self.term.destination_vrf))
        ret_str.append("set vrf {1} router bgp address-family ipv6-unicast route-import from-vrf list {0}".format(self.term.source_vrf, self.term.destination_vrf))

        return '\n'.join(t for t in ret_str if t)


class NVUESelectiveVRFRouteLeaking(aclgenerator.ACLGenerator):

    SUFFIX = '.yml'

    #  def _TranslatePolicy(self, pol, exp_info):
        #  self.lines = []
        #  for header, terms in pol.filters:
            #  pass

    def _TranslatePolicy(self, pol, exp_info):
        self.target = []
        for header, terms in pol.filters:
            for term in terms:
                self.target.append(str(Term(term)))

    def __str__(self):
        return '\n'.join(self.target)
