# Extensions to ethereumjs-tx adding transaction signing support using Azure Key Vault

## Installation
`npm install ethereumjs-tx-keyvault`

## Example usage

````javascript
const TxExtensions = require("ethereumjs-tx-keyvault")

const KeyVault = require("azure-keyvault")
const EthereumTx = require("ethereumjs-tx")

const client = KeyVault.createKeyVaultClient(/* client credentials */)

const txParams = {
    nonce: '0x34f', // Replace by nonce for your account on geth node
    gasPrice: '0x09184e72a000',
    gasLimit: '0x27100',
    to: '0x0d8e50b8849f59f25078bb9e2d9014b9a540dcab',
    value: '0xde0b6b3a7640000'
}
var transaction = new EthereumTx(txParams)

TxExtensions.sign(transaction, client, "your_vault_uri", "your_key_name", "your_key_version")
    .then(signature => {
        Object.assign(transaction, signature)

        console.log("Transaction verified: " + transaction.verifySignature())
     })
  ````
