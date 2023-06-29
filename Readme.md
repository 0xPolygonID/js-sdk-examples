Place actual circuits to folder e.g to`./circuits`  
you can download the latest files from `https://iden3-circuits-bucket.s3.eu-west-1.amazonaws.com/latest.zip`



To run scripts them, please set following variables:
```
export WALLET_KEY="...key in hex format with matic balance"
export RPC_URL="...url to polygon mumbai network rpc node"
export RHS_URL="..reverse hash service url"
export CONTRACT_ADDRESS="..state v2 contract address in the mumbai network"
export CIRCUITS_PATH="..path to the circuits folder"
```

Run:
```bash
npm i
npm run start
```
