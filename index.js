"use strict"

const EthereumTx = require("ethereumjs-tx")
const KeyVault = require("azure-keyvault")
const BN = require("bn.js")
const assert = require("assert")
const secp256k1 = require("secp256k1")
const _ = require("underscore")

const CURVE_ORDER = new BN(Buffer.from('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141', 'hex'))
const HALF_CURVE_ORDER = CURVE_ORDER.clone().ishrn(1)

var isHigh = function (num) {
    return num.ucmp(HALF_CURVE_ORDER) === 1
}

var makeCanonical = function (buffer) {
    var r = new BN(buffer.slice(0, 32))
    var s = new BN(buffer.slice(32, 64))

    if (isHigh(s)) {
        s = CURVE_ORDER.sub(s)
    }
    return Buffer.concat([r.toBuffer(), s.toBuffer()])
}

var Extensions = function () {
    function Extensions() {
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
    Extensions.prototype.sign = function (tx, client, vaultUri, keyName, keyVersion) {
        assert.equal(true, tx instanceof EthereumTx, "Transaction must be of type 'require(\"ethereumjs-tx\")'")
        assert.equal(true, client instanceof KeyVault.KeyVaultClient, "Client must be of type 'require(\"azure-keyvault\").KeyVaultClient'")

        return new Promise((resolve, reject) => {
            client.getKey(vaultUri, keyName, keyVersion, null, function (getErr, getKeyBundle) {
                if (getErr) {
                    reject(getErr)
                    return
                }
                const msgHash = tx.hash(false)

                client.sign(vaultUri, keyName, keyVersion, "ECDSA256", msgHash, null, function (signErr, signature) {
                    if (signErr) {
                        reject(signErr)
                        return
                    }
                    const pubKey = Buffer.concat([Uint8Array.from([4]), getKeyBundle.key.x, getKeyBundle.key.y])
                    const sig = makeCanonical(Buffer.from(signature.result))

                    var sigObj = {
                        r: sig.slice(0, 32),
                        s: sig.slice(32, 64)
                    }

                    for (var i = 0; i < 4; i++) {
                        const recoveredPubKey = secp256k1.recover(msgHash, sig, i, false)
                        if (_.isEqual(pubKey, recoveredPubKey)) {
                            sigObj.v = Buffer.from([i + 27])
                            break
                        }
                    }

                    console.debug("secp256k1 verify: " + secp256k1.verify(msgHash, sig, pubKey))
                    resolve(sigObj)
                })
            })
        })
    }
    return Extensions
}()

module.exports = Extensions