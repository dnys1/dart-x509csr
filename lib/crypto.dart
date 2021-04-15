/*
 *  lib/crypto.dart
 *
 *  David Janes
 *  2019-03-15
 */

import 'package:pointycastle/export.dart';
import 'package:asn1lib/asn1lib.dart';

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

/*
 */
AsymmetricKeyPair rsaGenerateKeyPair({int chunkSize = 2048}) {
  final keyParams =
      RSAKeyGeneratorParameters(BigInt.parse('65537'), chunkSize, 12);

  final secureRandom = FortunaRandom();
  final random = Random.secure();
  final seeds = <int>[];
  for (var i = 0; i < 32; i++) {
    seeds.add(random.nextInt(255));
  }
  secureRandom.seed(KeyParameter(Uint8List.fromList(seeds)));

  final rngParams = ParametersWithRandom(keyParams, secureRandom);
  final k = RSAKeyGenerator();
  k.init(rngParams);

  return k.generateKeyPair();
}

/*
 */
Uint8List rsaSign(Uint8List inBytes, RSAPrivateKey privateKey) {
  final signer = Signer('SHA-256/RSA');
  signer.init(true, PrivateKeyParameter<RSAPrivateKey>(privateKey));

  final signature = signer.generateSignature(inBytes) as RSASignature;
  return signature.bytes;
}

/*
https://github.com/dart-lang/sdk/issues/32803#issuecomment-387405784
 */
Uint8List _bigIntToBytes(BigInt n) {
  final bytes = (n.bitLength + 7) >> 3;

  final b256 = BigInt.from(256);
  final result = Uint8List(bytes);

  for (var i = 0; i < bytes; i++) {
    result[i] = n.remainder(b256).toInt();
    n = n >> 8;
  }

  return result;
}

Uint8List rsaPublicKeyModulusToBytes(RSAPublicKey publicKey) =>
    _bigIntToBytes(publicKey.modulus!);
Uint8List rsaPublicKeyExponentToBytes(RSAPublicKey publicKey) =>
    _bigIntToBytes(publicKey.exponent!);
Uint8List rsaPrivateKeyToBytes(RSAPrivateKey privateKey) =>
    _bigIntToBytes(privateKey.modulus!);

List<String> _chunked(String encoded, {int chunkSize = 64}) {
  final chunks = <String>[];

  for (var i = 0; i < encoded.length; i += chunkSize) {
    var end = (i + chunkSize < encoded.length) ? i + chunkSize : encoded.length;
    chunks.add(encoded.substring(i, end));
  }

  return chunks;
}

String encodeCSRToPem(ASN1Object csr) {
  final chunks = _chunked(base64.encode(csr.encodedBytes));

  return '-----BEGIN CERTIFICATE REQUEST-----\r\n' +
      chunks.join('\r\n') +
      '\r\n-----END CERTIFICATE REQUEST-----\r\n';
}

// from https://gist.github.com/proteye/982d9991922276ccfb011dfc55443d74
String encodeRSAPublicKeyToPem(RSAPublicKey publicKey) {
  final algorithmSeq = ASN1Sequence();
  final algorithmAsn1Obj = ASN1Object.fromBytes(Uint8List.fromList(
      [0x6, 0x9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0xd, 0x1, 0x1, 0x1]));
  final paramsAsn1Obj = ASN1Object.fromBytes(Uint8List.fromList([0x5, 0x0]));
  algorithmSeq.add(algorithmAsn1Obj);
  algorithmSeq.add(paramsAsn1Obj);

  final publicKeySeq = ASN1Sequence();
  publicKeySeq.add(ASN1Integer(publicKey.modulus!));
  publicKeySeq.add(ASN1Integer(publicKey.exponent!));
  final publicKeySeqBitString =
      ASN1BitString(Uint8List.fromList(publicKeySeq.encodedBytes));

  final topLevelSeq = ASN1Sequence();
  topLevelSeq.add(algorithmSeq);
  topLevelSeq.add(publicKeySeqBitString);
  final dataBase64 = base64.encode(topLevelSeq.encodedBytes);
  final chunks = _chunked(dataBase64);

  return '''-----BEGIN PUBLIC KEY-----\r\n${chunks.join('\r\n')}\r\n-----END PUBLIC KEY-----\r\n''';
}

String encodeRSAPrivateKeyToPem(RSAPrivateKey privateKey) {
  final version = ASN1Integer(BigInt.from(0));

  final algorithmSeq = ASN1Sequence();
  final algorithmAsn1Obj = ASN1Object.fromBytes(Uint8List.fromList(
      [0x6, 0x9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0xd, 0x1, 0x1, 0x1]));
  final paramsAsn1Obj = ASN1Object.fromBytes(Uint8List.fromList([0x5, 0x0]));
  algorithmSeq.add(algorithmAsn1Obj);
  algorithmSeq.add(paramsAsn1Obj);

  final privateKeySeq = ASN1Sequence();
  final modulus = ASN1Integer(privateKey.n!);
  final publicExponent = ASN1Integer(BigInt.parse('65537'));
  final privateExponent = ASN1Integer(privateKey.privateExponent!);
  final p = ASN1Integer(privateKey.p!);
  final q = ASN1Integer(privateKey.q!);
  final dP = privateKey.privateExponent! % (privateKey.p! - BigInt.from(1));
  final exp1 = ASN1Integer(dP);
  final dQ = privateKey.privateExponent! % (privateKey.q! - BigInt.from(1));
  final exp2 = ASN1Integer(dQ);
  final iQ = privateKey.q!.modInverse(privateKey.p!);
  final co = ASN1Integer(iQ);

  privateKeySeq.add(version);
  privateKeySeq.add(modulus);
  privateKeySeq.add(publicExponent);
  privateKeySeq.add(privateExponent);
  privateKeySeq.add(p);
  privateKeySeq.add(q);
  privateKeySeq.add(exp1);
  privateKeySeq.add(exp2);
  privateKeySeq.add(co);
  final publicKeySeqOctetString =
      ASN1OctetString(Uint8List.fromList(privateKeySeq.encodedBytes));

  final topLevelSeq = ASN1Sequence();
  topLevelSeq.add(version);
  topLevelSeq.add(algorithmSeq);
  topLevelSeq.add(publicKeySeqOctetString);
  final dataBase64 = base64.encode(topLevelSeq.encodedBytes);

  final chunks = _chunked(dataBase64);

  return '''-----BEGIN PRIVATE KEY-----\r\n${chunks.join('\r\n')}\r\n-----END PRIVATE KEY-----\r\n''';
}
