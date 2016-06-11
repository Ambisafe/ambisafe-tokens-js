'use strict'

var TokenSigner = require('./index').TokenSigner;
var TokenVerifier = require('./index').TokenVerifier;
var decodeToken = require('./index').decodeToken;
var MissingParametersError = require('./index').MissingParametersError;

var rawPrivateKey = '278a5de700e29faae8e40e366ec5012b5ec63d36ec77e8a2417154cc1d25383f';

/*

sha3(1234, "test");
0x5cd5ad1ce00bed4f85eec5d63baac2ce09a5ddc4918aaa5dcc1551d81527d4f7

*/

test('TokenSigner', function(t) {
    t.plan(5)

    var tokenSigner = new TokenSigner('ES256K', rawPrivateKey)
    t.ok(tokenSigner, 'token signer should have been created')

    var token = tokenSigner.sign(sampleDecodedToken.payload)
    t.ok(token, 'token should have been created')
    t.equal(typeof token, 'string', 'token should be a string')
    
    var decodedToken = decodeToken(token)
    t.equal(JSON.stringify(decodedToken.header), JSON.stringify(sampleDecodedToken.header), 'decodedToken header should match the reference header')
    t.equal(JSON.stringify(decodedToken.payload), JSON.stringify(sampleDecodedToken.payload), 'decodedToken payload should match the reference payload')
})

test('TokenVerifier', function(t) {
    t.plan(2)

    var tokenVerifier = new TokenVerifier('ES256K', rawPublicKey)
    t.ok(tokenVerifier, 'token verifier should have been created')
    
    var verified = tokenVerifier.verify(sampleToken)
    t.equal(verified, true, 'token should have been verified')
})

test('decodeToken', function(t) {
    t.plan(2)

    var decodedToken = decodeToken(sampleToken)
    t.ok(decodedToken, 'token should have been decoded')
    t.equal(JSON.stringify(decodedToken.payload), JSON.stringify(sampleDecodedToken.payload), 'decodedToken payload should match the reference payload')
})

test('SECP256K1Client', function(t) {
    t.plan(2)

    var derivedRawPublicKey = SECP256K1Client.privateKeyToPublicKey(rawPrivateKey)
    t.ok(derivedRawPublicKey, 'raw public key should have been derived')
    t.equal(derivedRawPublicKey, rawPublicKey, 'derived raw public key should match the reference value')
})
