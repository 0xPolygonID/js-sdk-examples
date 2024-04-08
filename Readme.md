# js-sdk-examples

## Setup

1. Download the zk circuits into `./circuits` by running `dl_circuits.sh`. This will download the latest files from `https://iden3-circuits-bucket.s3.eu-west-1.amazonaws.com/latest.zip`

    ```bash
    ./dl_circuits.sh
    ```

2. Copy over the `.env.example` into `.env`  
  You'll need to fill in `RPC_URL` and `WALLET_KEY` with your own endpoint and key respectively. The default env vars assume you will be using the Polygon Amoy network.

    ```bash
    cp .env.example .env
    ```

    `example.env`

    ```bash
    # reverse hash service url
    RHS_URL="https://rhs-staging.polygonid.me" 
    # state v2 contract address in the amoy network
    CONTRACT_ADDRESS="0x1a4cC30f2aA0377b0c3bc9848766D90cb4404124"
    # path to the circuits folder
    CIRCUITS_PATH="./circuits" 
    # url to polygon amoy network rpc node
    RPC_URL="" 
    # key in hex format with matic balance
    WALLET_KEY="" 
    # MongoDB connection string, uses in memory Mongo server if not specified
    MONGO_DB_CONNECTION=""

    ```

3. Install dependencies

    ```bash
    npm i 
    ```

## Run

You can run each example function independently:

```bash
npm run start -- [function]
```

The [function] should be replaced with one of the following options:

- identityCreation  
- issueCredential  
- transitState
- transitStateThirdPartyDID
- generateProofs
- handleAuthRequest
- handleAuthRequestWithProfiles
- handleAuthRequestNoIssuerStateTransition
- generateProofsMongo
- handleAuthRequestMongo

To run all examples

```bash
npm run start
```
