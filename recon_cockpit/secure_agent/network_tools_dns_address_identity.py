"""Compiled public DNS fixture identity without importing the owner service.

Canonical requests/responses use transaction ID zero; native request IDs are
validated by the owner and are not authority inputs. Tests bind every compiled
hash to the separate finite owner fixture.
"""

from types import MappingProxyType

CANONICAL_QUERIES_BY_TOOL = MappingProxyType({'dig_dns_aaaa_v1': b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\nharbord'
                    b'esk\x04test\x00\x00\x1c\x00\x01',
 'dig_dns_ptr_v1': b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x011\x010'
                   b'\x010\x03127\x07in-addr\x04arpa\x00\x00\x0c\x00\x01'})

QUERY_BYTES_BY_TOOL = MappingProxyType({'dig_dns_aaaa_v1': 33, 'dig_dns_ptr_v1': 40})

QUERY_SHA256_BY_TOOL = MappingProxyType({'dig_dns_aaaa_v1': '8874de903974d2404a141ef408cdcc0a06ef9c3a8c373f9995e284d2a8bc1c89',
 'dig_dns_ptr_v1': 'a5fea597f0b7a99b7323e01cd03761cb622cccaa8217435a107ca8424e6c0acb'})

RESPONSE_SHA256_BY_CASE = MappingProxyType({'dig-aaaa-ok': '24c419578f2cddccd91c7015ea97d54575ecfe145b3e0e7aa6fe5277c303f6cc',
 'dig-aaaa-single': 'd0d90734c2b86a1a3250bbf31585b885b3a5977b292b496f7f6e4f91072b18d3',
 'dig-aaaa-four': 'afe7e0be22eef1758c0c923950f8c4f7c2f2f2d9bc1f5109f8125d33c18d7fcd',
 'dig-aaaa-nodata': '8ff131eb6d9d13321e6590ed3032d1b032118f008b34388a68d54f44fbde0124',
 'dig-aaaa-nxdomain': '1882eb28d7bf551c786f597a0896831cdfc5043f7829250397522c8b04e0f7b9',
 'dig-aaaa-fragmented': '24c419578f2cddccd91c7015ea97d54575ecfe145b3e0e7aa6fe5277c303f6cc',
 'dig-aaaa-injected': '48cedf1f7661be76e4135740df950bf75fb75566e6d51cc94a86f8b83fcd08de',
 'dig-aaaa-malformed': '9650a323c857e310dae81f5c57ae71178afc489ee329a7a8f682cd5c29a82dca',
 'dig-aaaa-record-limit': 'bc27d827eb98d18b997919fb6380efd5eac7921bfe55c92397305fa9dcfaa529',
 'dig-aaaa-wrong-question': 'c9416af34e55b5ee69f836fcd14bd9a1c59ef181456ef6aec137d42da14ad9b5',
 'dig-aaaa-wrong-type': 'e93de527caad26b9ec7cb4603932f6f2bde96fc92fd9bf5a9cb509af2862c24b',
 'dig-aaaa-alias': 'a42f89735c61f1f5bc3e79acedb43859b6c1c12fb64d10f11efb5f293e05602e',
 'dig-aaaa-duplicate': 'c3c213e65dfe603a121bc09b3c65c9bd6870a203881bce52df50ce09da2c2ae6',
 'dig-aaaa-truncated': 'b28b917f523e65ec4e8be8f64fa0b81fb23470f439a988b68bc2a7a69451ef86',
 'dig-aaaa-refused': 'ac7abaa1334c1354fa1b06d027a88d11f8a07b776759c477cf23662fe0554d3d',
 'dig-aaaa-stalled': None,
 'dig-aaaa-output-limit': '43916f306718cd077c437e4b81da5f36778284e503a1d6c99dba8505efaf1b6e',
 'dig-aaaa-malformed-value': '77b168cd267dbfce8ebbfe6d7a8260f06a13173e4c77c43dbb052575f8a32bb5',
 'dig-aaaa-mapped': '9e13cfc732ccdfcca1325d7abfe820362216d9073762029e5cbe2767af607521',
 'dig-ptr-ok': '0d3f3ee6dea211fbe1049ad38faa8262adc076a2a051e952fbe46f8a8a067bde',
 'dig-ptr-single': '10eadf1df29897bcdf4fc01ef12bbf6a7af9013cd540ab1d72d5f95385782530',
 'dig-ptr-four': '314f435547a92f81449a0563d5c83f9d398043b83ea5d2b287348d377f18fdd7',
 'dig-ptr-nodata': 'da8264efac0b9be92e82f27be6b2d365b349e4b67808f4ca4579ea679a880a73',
 'dig-ptr-nxdomain': '978e4cbb872e7bd9d26930e68e0dc7bd97de366c73051fa612c8b2eb0bef3dcb',
 'dig-ptr-fragmented': '0d3f3ee6dea211fbe1049ad38faa8262adc076a2a051e952fbe46f8a8a067bde',
 'dig-ptr-injected': 'c51758621ec3cc19bb73cb9d35115424a797f896d5d26702dd9c1ae616cb3365',
 'dig-ptr-malformed': '25353810490eab7b7fd031ae61f76dce1fbd47ba4ef16ae76b4520a3e6bb074a',
 'dig-ptr-record-limit': '5735c1ee6bca9bee6f4656f7079166d58c8d3ff754fae4280a90bb4e2c6d57e0',
 'dig-ptr-wrong-question': '6ef92c8ed77e673bfc4923e12f75303f8e47c0df4e0b31f158e22a9024052e91',
 'dig-ptr-wrong-type': 'cdfbe880f6bfaa468ec77520927d7a3b24ff096c5ddbefd39f5684ae684986c7',
 'dig-ptr-alias': '6df32f1cb5a34c05a33de74cdfc05b9c59c281a0d8fc81b231061337ad1763b0',
 'dig-ptr-duplicate': '704691e90e81d519449f03bad97ab6f70b29f8cf3c1a45b04ac21e432b6206a9',
 'dig-ptr-truncated': 'a3395f55a58193a6777f69dc953cb6198a708ed09d088de2cb15eb1d1ef1d50c',
 'dig-ptr-refused': 'c41653dda90146dc8f478cd28c34dfb7e6eea68671a8d1aa88369371c5697f36',
 'dig-ptr-stalled': None,
 'dig-ptr-output-limit': '7ccda456d0496008d4436ed22b3299e1922e1e8c4db533b13292e808513f8ad3',
 'dig-ptr-malformed-value': 'a784c2f256051543716a3c3174f9b9f482cdf70940f42836433ffb50e94f818c',
 'dig-ptr-root': 'ec53ac68fa34e105ed5f301fa9199bb5d7d8da01d68d787635e6b1690732df04'})

