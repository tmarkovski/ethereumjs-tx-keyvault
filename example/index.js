const txExt = require("../index.js")
const KeyVault = require("azure-keyvault")
const EthereumTx = require("ethereumjs-tx")
const AuthenticationContext = require("adal-node").AuthenticationContext;

const clientId = "<to-be-filled>";
const clientSecret = "<to-be-filled>";
const vaultUri = "<to-be-filled>";

// Setup key vault client and credentials
const authenticator = function (challenge, callback) {
    const context = new AuthenticationContext(challenge.authorization);
    return context.acquireTokenWithClientCredentials(challenge.resource, clientId, clientSecret, function (err, tokenResponse) {
        if (err) throw err
        const authorizationValue = tokenResponse.tokenType + ' ' + tokenResponse.accessToken
        return callback(null, authorizationValue)
    })
}
const credentials = new KeyVault.KeyVaultCredentials(authenticator)
const client = new KeyVault.KeyVaultClient(credentials);

// Create a sample transaction
const txParams = {
    nonce: '0x00',
    gasPrice: '0x09184e72a000',
    gasLimit: '0x2710',
    to: '0x0000000000000000000000000000000000000000',
    value: '0x00',
    data: '0x7f7465737432000000000000000000000000000000000000000000000000000000600057',
    // EIP 155 chainId - mainnet: 1, ropsten: 3
    chainId: 3
}
const tx = new EthereumTx(txParams)

// Sign the transaction and log verification results
txExt.sign(tx, client, vaultUri, "alice", "")
    .then(signature => {
        Object.assign(tx, signature)
        console.log("Signature verification: " + tx.verifySignature())

        // Print transaction hash. Can be sent directly to geth using 'sendRawTransaction'
        const txHash = "0x" + Buffer.from(tx.serialize()).toString("hex")
        console.log("Transaction hash: " + txHash)
    })