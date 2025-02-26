/*
 * lib/rsa.dart
 *
 * David Janes
 * 2018-03-13
 *
 * Copyright [2019] David P. Janes
 *
 * Licensed under the Apache License, Version 2.0 (the 'License');
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an 'AS IS' BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import 'package:x509csr/x509csr.dart';

import 'package:pointycastle/export.dart';
import 'package:asn1lib/asn1lib.dart';

ASN1Object _encodeDN(Map<String, String> d) {
  var dn = ASN1Sequence();

  d.forEach((name, value) {
    final oid = ASN1ObjectIdentifier.fromName(name);

    ASN1Object ovalue;
    switch (name.toUpperCase()) {
      case 'C':
        {
          ovalue = ASN1PrintableString(value);
        }
        break;
      case 'CN':
      case 'O':
      case 'L':
      case 'S':
      default:
        {
          ovalue = ASN1UTF8String(value);
        }
        break;
    }

    var pair = ASN1Sequence();
    pair.add(oid);
    pair.add(ovalue);

    var pairset = ASN1Set();
    pairset.add(pair);

    dn.add(pairset);
  });

  return dn;
}

/*
 */
ASN1Sequence _makePublicKeyBlock(RSAPublicKey publicKey) {
  final blockEncryptionType = ASN1Sequence();
  blockEncryptionType.add(ASN1ObjectIdentifier.fromName('rsaEncryption'));
  blockEncryptionType.add(ASN1Null());

  final publicKeySequence = ASN1Sequence();
  publicKeySequence.add(ASN1Integer(publicKey.modulus!));
  publicKeySequence.add(ASN1Integer(publicKey.exponent!));

  final blockPublicKey = ASN1BitString(publicKeySequence.encodedBytes);

  final outer = ASN1Sequence();
  outer.add(blockEncryptionType);
  outer.add(blockPublicKey);

  return outer;
}

/*
 */
ASN1Object makeRSACSR(
  Map<String, String> dn,
  RSAPrivateKey privateKey,
  RSAPublicKey publicKey,
) {
  final encodedDN = _encodeDN(dn);

  final blockDN = ASN1Sequence();
  blockDN.add(ASN1Integer(BigInt.from(0)));
  blockDN.add(encodedDN);
  blockDN.add(_makePublicKeyBlock(publicKey));
  blockDN.add(ASN1Null(tag: 0xA0)); // let's call this WTF

  final blockProtocol = ASN1Sequence();
  blockProtocol.add(ASN1ObjectIdentifier.fromName('sha256WithRSAEncryption'));
  blockProtocol.add(ASN1Null());

  final outer = ASN1Sequence();
  outer.add(blockDN);
  outer.add(blockProtocol);
  outer.add(ASN1BitString(rsaSign(blockDN.encodedBytes, privateKey)));
  return outer;
}
