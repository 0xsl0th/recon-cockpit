"""Compiled public fixture identity; importing it cannot start an owner.

Canonical request id is the single byte 0x01. Native request ids remain
validated by the owner and are never authority inputs. Portable contracts bind
these constants to all twenty fixture responses.
"""

from types import MappingProxyType

CANONICAL_REQUEST = b'05\x02\x01\x01\x04\x14recon-fixture-public\xa5\x1a\x02\x01\x01\x02\x01\x00\x02\x01\x040\x0f0\r\x06\t+\x06\x01\x02\x01\x02\x02\x01\x02\x05\x00'
CANONICAL_REQUEST_BYTES = 55
CANONICAL_REQUEST_SHA256 = 'e913360a3c52e9c0970c4360748d4f705e887b2a97f7569ebb5b1afa3b68613d'
CANONICAL_RESPONSE_SHA256 = MappingProxyType({'snmp-page-ok': '48a372c1145ca351a1ab27a574f6e642604f8b6464ae1557b3335913ef059d1e',
 'snmp-page-empty': '5bc29d6df2758a93bb7aea5f498a81cd37f29c81e50a30e39c0a8f85a92bf69a',
 'snmp-page-end-of-view': '5e40471a86533c6e6475395cc2a71cb17f94eaa87d6a12eb1e69a66c9f11c2d6',
 'snmp-page-outside-subtree': 'd90aabcf71d089aa78f2e5ab227798da8c7c12a0c1b9f5660cafb2bce7b89bff',
 'snmp-page-mixed-boundary': '7d1bc2a89eaa7bf9533dc705ed5c129865364b801e15748cc92607c47cc4e7b8',
 'snmp-page-end-after-rows': 'fa5c638053d6ef3546f6cbac8dacd987b1f53218c3c8497ae6d28a1aac35615c',
 'snmp-page-fragmented': '48a372c1145ca351a1ab27a574f6e642604f8b6464ae1557b3335913ef059d1e',
 'snmp-page-injected': '6c84b456c44f4cc309ed6cce9834286d2545a8b5082f72b5abe5fb4dea410b82',
 'snmp-page-short': '6f57034491d1280325f4dbb62cf8a8f005b38a4e44f08d3b6a4105574d205545',
 'snmp-page-empty-page': 'ce7ff98ac1693dab9e162754dea01b8b701b3281785261c7eb7f97eb44e7e979',
 'snmp-page-nonincreasing': '2375ae0db8cab2f4d8ad8bd853591a668d7b65ea9ee3fcb5d2e170ffe1a6c4c7',
 'snmp-page-duplicate': '1f4efb68b6577b7f51e033102229b6b32857bf8392bbfaf5bf653a9607ff3320',
 'snmp-page-wrong-type': 'b409d6649ec2e0d6224c5bc71f7f8ee1cf6a500571a410b5756a23e0d06c7fc6',
 'snmp-page-extra-varbind': '27dcb8b662b870200b62841a7036a41a65402fd955086fc05280c23a479ee475',
 'snmp-page-after-end': '87a5b2bfaa1374a4683514189526c880d7b83f91f4e787fe74b1f0271676ecf9',
 'snmp-page-malformed': '9dd6deb17adb1b3381b253bc934b43ad585b97d2eab8e1d5ef0d2daa8ff9e8c3',
 'snmp-page-truncated': '8b1cb71d8b2102447e6cf781b15acfa4d18ce90a2ca9854e1732ea832fb810de',
 'snmp-page-denied': 'ef5d99d265465cf53c22f593a44a368da622fd29b1dac219ae75684c9500ffb4',
 'snmp-page-stalled': None,
 'snmp-page-output-limit': '810cfba1adff759fc9096c419410bb0cc28b7cf799042783389c10f0a601fe4d'})
