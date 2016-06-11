'use strict'

var base64url = require('base64url');
var ethUtil = require('ethereumjs-util');
var decodeToken = require('./decode');

function TokenSigner(signingAlgorithm, rawPrivateKey) {
    if (!(signingAlgorithm && rawPrivateKey)) {
        throw new MissingParametersError('a signing algorithm and private key are required')
    }
    if (typeof signingAlgorithm !== 'string') {
        throw 'signing algorithm parameter must be a string'
    }
    signingAlgorithm = signingAlgorithm.toUpperCase()
    if (!CryptoClients.hasOwnProperty(signingAlgorithm)) {
        throw 'invalid signing algorithm'
    }
    this.tokenType = 'EWT'
    this.cryptoClient = CryptoClients[signingAlgorithm]
    this.rawPrivateKey = rawPrivateKey
}

TokenSigner.prototype.header = function() {
    return {typ: this.tokenType, alg: this.cryptoClient.algorithmName}
}

TokenSigner.prototype.sign = function(payload) {
    var tokenParts = []

    // add in the header
    var encodedHeader = base64url.encode(JSON.stringify(this.header()))
    tokenParts.push(encodedHeader)

    // add in the payload
    var encodedPayload = base64url.encode(JSON.stringify(payload))
    tokenParts.push(encodedPayload)

    // prepare the message
    var values = [];

    var opHash = ethUtil.sha3( Buffer.concat(values));

    // sign the message and add in the signature
    var sig = ethUtil.ecsign(opHash, this.privKey);

    var ec = new EC();
    var signature = new ec.Signature({
      r: sig.r,
      s: sig.s,
      recoveryParam: sig.v - 27
    }, 'secp256k1');
    tokenParts.push(signature);

    // return the token
    return tokenParts.join('.')
}

module.exports = TokenSigner