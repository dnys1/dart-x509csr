/*
 *  example/x509csr.dart
 *
 *  David Janes
 *  2019-03-15
 */
import 'package:x509csr/x509csr.dart';

import 'package:pointycastle/export.dart';
import 'package:asn1lib/asn1lib.dart';

void main(List<String> arguments) {
  final keyPair = rsaGenerateKeyPair();

  ASN1ObjectIdentifier.registerFrequentNames();
  final dn = {
    'CN': 'www.davidjanes.com',
    'O': 'Consensas',
    'L': 'Toronto',
    'ST': 'Ontario',
    'C': 'CA',
  };

  final encodedCSR = makeRSACSR(
    dn,
    keyPair.privateKey as RSAPrivateKey,
    keyPair.publicKey as RSAPublicKey,
  );

  print(encodeCSRToPem(encodedCSR));
  print(encodeRSAPublicKeyToPem(keyPair.publicKey as RSAPublicKey));
  print(encodeRSAPrivateKeyToPem(keyPair.privateKey as RSAPrivateKey));
}
