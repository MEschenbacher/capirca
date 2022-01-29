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

_PLATFORM = 'nvue-selective-vrf-route-leaking'


class Term(aclgenerator.Term):
    """A single vrf leaking term, mostly used for the __str__() method.

  Args:
    term: policy.Term object.
    filter_type: IP address version number.
  """

    def __init__(self, term):
        super().__init__(term)
        self.term = term
        self.term.source_vrf = next(iter([ x.parent_token for x in  self.term.source_address if hasattr(x, 'parent_token')]), None).replace('VRF_', '')
        self.term.destination_vrf = next(iter([ x.parent_token for x in  self.term.destination_address if hasattr(x, 'parent_token')]), None).replace('VRF_', '')

    def __str__(self):
        ret_str = []

        if not self.term.source_vrf or not self.term.destination_vrf:
            return

        common = "router policy prefix-list PL4{}to{}".format(self.term.source_vrf, self.term.destination_vrf)
        ret_str.append("unset {}".format(common))
        ret_str.append("set {} type ipv4".format(common))
        ret_str.append("unset {}".format(common))
        ret_str.append("set {} type ipv6".format(common))
        for address in self.term.destination_address:
            ret_str.append("set {} rule XXX match {}".format(common, address))
            ret_str.append("set {} rule XXX action permit".format(common))

# this currently fails (see cumulus role and mellanox case)
        ret_str.append("set router policy route-map {0}to{1} rule 10 match ip-prefix-list PL6{0}to{1}".format(self.term.source_vrf, self.term.destination_vrf))
        ret_str.append("set router policy route-map {0}to{1} rule 10 action accept".format(self.term.source_vrf, self.term.destination_vrf))
        ret_str.append("set router policy route-map {0}to{1} rule 20 match ip-prefix-list PL4{0}to{1}".format(self.term.source_vrf, self.term.destination_vrf))
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
