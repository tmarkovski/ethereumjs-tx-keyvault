"use strict"

const EthereumTx = require("ethereumjs-tx")
const KeyVault = require("azure-keyvault")

const secp256k1 = require("secp256k1")
const BN = require("bn.js")

const assert = require("assert")
const _ = require("underscore")

// The order of the curve 'n'. See: https://en.bitcoin.it/wiki/Secp256k1
const CURVE_ORDER = new BN(Buffer.from('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141', 'hex'))
const HALF_CURVE_ORDER = CURVE_ORDER.clone().ishrn(1)

function isHigh(num) {
    return num.ucmp(HALF_CURVE_ORDER) === 1
}

function makeCanonical(buffer) {
    let r = new BN(buffer.slice(0, 32))
    let s = new BN(buffer.slice(32, 64))

    if (isHigh(s)) {
        s = CURVE_ORDER.sub(s)
    }
    return Buffer.concat([r.toBuffer(), s.toBuffer()])
}

/**
 * Signs a transaction using azure key vault
 * @param {EthereumTx} tx the transaction object to sign
 * @param {KeyVault.KeyVaultClient} client the key vault client object
 * @param {String} vaultUri the vault URI
 * @param {String} keyName the name of the EC key
 * @param {String} keyVersion the version of the key
 * @return {Buffer} the signed transaction object
 */
const sign = async function (tx, client, vaultUri, keyName, keyVersion) {
    assert.equal(true, tx instanceof EthereumTx, "Transaction must be of type 'require(\"ethereumjs-tx\")'")
    assert.equal(true, client instanceof KeyVault.KeyVaultClient, "Client must be of type 'require(\"azure-keyvault\").KeyVaultClient'")

    const msgHash = tx.hash(false)

    const keyBundle = await client.getKey(vaultUri, keyName, keyVersion)
    const pubKey = Buffer.concat([Uint8Array.from([4]), keyBundle.key.x, keyBundle.key.y])

    const signResult = await client.sign(vaultUri, keyName, keyVersion, "ECDSA256", msgHash)
    const signature = makeCanonical(Buffer.from(signResult.result))

    let v = -1
    // Recover the public key by comparing the recovered key with the actual public key.
    // If a match is found, that's the value of 'v'
    for (let i = 0; i <= 1; i++) {
        const recoveredPubKey = secp256k1.recover(msgHash, signature, i, false)
        if (_.isEqual(pubKey, recoveredPubKey)) {
            v = i
            break
        }
    }
    assert.equal(true, v === 0 || v === 1)
    console.debug("secp256k1 verify: " + secp256k1.verify(msgHash, signature, pubKey))

    // As per the EIP-155 spec, the value of 'v' is also dependent on the chain id.
    // See: https://github.com/ethereum/EIPs/blob/master/EIPS/eip-155.md#specification
    v += 27
    if (tx.getChainId() > 0) {
        v += tx.getChainId() * 2 + 8;
    }

    return {
        r: signature.slice(0, 32),
        s: signature.slice(32, 64),
        v: Buffer.from([v])
    }
}

module.exports = { sign: sign }