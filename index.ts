import { proving } from "@iden3/js-jwz";
const getCurveFromName = require("ffjavascript").getCurveFromName;
import { base64url as base64 } from "rfc4648";
import {
  BjjProvider,
  CredentialStorage,
  CredentialWallet,
  defaultEthConnectionConfig,
  EthStateStorage,
  ICredentialWallet,
  IDataStorage,
  Identity,
  IdentityCreationOptions,
  IdentityStorage,
  IdentityWallet,
  IIdentityWallet,
  InMemoryDataSource,
  InMemoryMerkleTreeStorage,
  InMemoryPrivateKeyStore,
  KMS,
  KmsKeyType,
  Profile,
  W3CCredential,
  CredentialRequest,
  EthConnectionConfig,
  CircuitStorage,
  CircuitData,
  FSKeyLoader,
  CircuitId,
  IStateStorage,
  ProofService,
  ZeroKnowledgeProofRequest,
  PackageManager,
  AuthorizationRequestMessage,
  PROTOCOL_CONSTANTS,
  AuthHandler,
  AuthDataPrepareFunc,
  StateVerificationFunc,
  DataPrepareHandlerFunc,
  VerificationHandlerFunc,
  IPackageManager,
  VerificationParams,
  ProvingParams,
  ZKPPacker,
  PlainPacker,
  ICircuitStorage,
  core,
  ZKPRequestWithCredential,
} from "@0xpolygonid/js-sdk";
import { ethers } from "ethers";
import path from "path";

const rhsUrl = process.env.RHS_URL as string;
const rpcUrl = process.env.RPC_URL as string;
const contractAddress = process.env.CONTRACT_ADDRESS as string;
const walletKey = process.env.WALLET_KEY as string;

const circuitsFolder = process.env.CIRCUITS_PATH as string;
function initDataStorage(): IDataStorage {
  let conf: EthConnectionConfig = defaultEthConnectionConfig;
  conf.contractAddress = contractAddress;
  conf.url = rpcUrl;

  var dataStorage = {
    credential: new CredentialStorage(new InMemoryDataSource<W3CCredential>()),
    identity: new IdentityStorage(
      new InMemoryDataSource<Identity>(),
      new InMemoryDataSource<Profile>()
    ),
    mt: new InMemoryMerkleTreeStorage(40),

    states: new EthStateStorage(defaultEthConnectionConfig),
  };

  return dataStorage;
}

async function initIdentityWallet(
  dataStorage: IDataStorage,
  credentialWallet: ICredentialWallet
): Promise<IIdentityWallet> {
  const memoryKeyStore = new InMemoryPrivateKeyStore();
  const bjjProvider = new BjjProvider(KmsKeyType.BabyJubJub, memoryKeyStore);
  const kms = new KMS();
  kms.registerKeyProvider(KmsKeyType.BabyJubJub, bjjProvider);

  return new IdentityWallet(kms, dataStorage, credentialWallet);
}

async function initCredentialWallet(
  dataStorage: IDataStorage
): Promise<CredentialWallet> {
  return new CredentialWallet(dataStorage);
}

async function initCircuitStorage(): Promise<ICircuitStorage> {
  const circuitStorage = new CircuitStorage(
    new InMemoryDataSource<CircuitData>()
  );

  const loader = new FSKeyLoader(path.join(__dirname, circuitsFolder));

  await circuitStorage.saveCircuitData(CircuitId.AuthV2, {
    circuitId: CircuitId.AuthV2,
    wasm: await loader.load(`${CircuitId.AuthV2.toString()}/circuit.wasm`),
    provingKey: await loader.load(
      `${CircuitId.AuthV2.toString()}/circuit_final.zkey`
    ),
    verificationKey: await loader.load(
      `${CircuitId.AuthV2.toString()}/verification_key.json`
    ),
  });

  await circuitStorage.saveCircuitData(CircuitId.AtomicQuerySigV2, {
    circuitId: CircuitId.AtomicQuerySigV2,
    wasm: await loader.load(
      `${CircuitId.AtomicQuerySigV2.toString()}/circuit.wasm`
    ),
    provingKey: await loader.load(
      `${CircuitId.AtomicQuerySigV2.toString()}/circuit_final.zkey`
    ),
    verificationKey: await loader.load(
      `${CircuitId.AtomicQuerySigV2.toString()}/verification_key.json`
    ),
  });

  await circuitStorage.saveCircuitData(CircuitId.StateTransition, {
    circuitId: CircuitId.StateTransition,
    wasm: await loader.load(
      `${CircuitId.StateTransition.toString()}/circuit.wasm`
    ),
    provingKey: await loader.load(
      `${CircuitId.StateTransition.toString()}/circuit_final.zkey`
    ),
    verificationKey: await loader.load(
      `${CircuitId.StateTransition.toString()}/verification_key.json`
    ),
  });

  await circuitStorage.saveCircuitData(CircuitId.AtomicQueryMTPV2, {
    circuitId: CircuitId.AtomicQueryMTPV2,
    wasm: await loader.load(
      `${CircuitId.AtomicQueryMTPV2.toString()}/circuit.wasm`
    ),
    provingKey: await loader.load(
      `${CircuitId.AtomicQueryMTPV2.toString()}/circuit_final.zkey`
    ),
    verificationKey: await loader.load(
      `${CircuitId.AtomicQueryMTPV2.toString()}/verification_key.json`
    ),
  });
  return circuitStorage;
}
async function initProofService(
  identityWallet: IIdentityWallet,
  credentialWallet: ICredentialWallet,
  stateStorage: IStateStorage,
  circuitStorage: ICircuitStorage
): Promise<ProofService> {
  return new ProofService(
    identityWallet,
    credentialWallet,
    circuitStorage,
    stateStorage
  );
}

async function identityCreation() {
  console.log("=============== key creation ===============");

  const dataStorage = initDataStorage();
  const credentialWallet = await initCredentialWallet(dataStorage);
  const identityWallet = await initIdentityWallet(
    dataStorage,
    credentialWallet
  );

  const { did, credential } = await identityWallet.createIdentity(
    "http://wallet.com/", // this is url that will be a part of auth bjj credential identifier
    {
      method: core.DidMethod.Iden3,
      blockchain: core.Blockchain.Polygon,
      networkId: core.NetworkId.Mumbai,
      rhsUrl,
    }
  );

  console.log("=============== did ===============");
  console.log(did.toString());
  console.log("=============== Auth BJJ credential ===============");
  console.log(JSON.stringify(credential));
}

async function issueCredential() {
  console.log("=============== issue credential ===============");

  const dataStorage = initDataStorage();
  const credentialWallet = await initCredentialWallet(dataStorage);
  const identityWallet = await initIdentityWallet(
    dataStorage,
    credentialWallet
  );

  const { did: userDID, credential: authBJJCredentialUser } =
    await identityWallet.createIdentity(
      "http://wallet.com/", // this is url that will be a part of auth bjj credential identifier, // url to check revocation status of auth bjj credential
      {
        method: core.DidMethod.Iden3,
        blockchain: core.Blockchain.Polygon,
        networkId: core.NetworkId.Mumbai,
        rhsUrl,
      }
    );

  console.log("=============== user did ===============");
  console.log(userDID.toString());

  const { did: issuerDID, credential: issuerAuthBJJCredential } =
    await identityWallet.createIdentity(
      "http://wallet.com/", // this is url that will be a part of auth bjj credential identifier
      {
        method: core.DidMethod.Iden3,
        blockchain: core.Blockchain.Polygon,
        networkId: core.NetworkId.Mumbai,
        rhsUrl, // url to check revocation status of auth bjj credential
      }
    );

  const credentialRequest: CredentialRequest = {
    credentialSchema:
      "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json/KYCAgeCredential-v3.json",
    type: "KYCAgeCredential",
    credentialSubject: {
      id: userDID.toString(),
      birthday: 19960424,
      documentType: 99,
    },
    expiration: 12345678888,
  };
  const credential = await identityWallet.issueCredential(
    issuerDID,
    credentialRequest,
    "http://wallet.com/", // host url that will a prefix of credential identifier
    {
      withRHS: rhsUrl, // reverse hash service is used to check
    }
  );

  console.log("===============  credential ===============");
  console.log(JSON.stringify(credential));

  await dataStorage.credential.saveCredential(credential);
}

async function generateProofs() {
  console.log("=============== generate proofs ===============");

  const dataStorage = initDataStorage();
  const credentialWallet = await initCredentialWallet(dataStorage);
  const identityWallet = await initIdentityWallet(
    dataStorage,
    credentialWallet
  );
  const circuitStorage = await initCircuitStorage();
  const proofService = await initProofService(
    identityWallet,
    credentialWallet,
    dataStorage.states,
    circuitStorage
  );

  const { did: userDID, credential: authBJJCredentialUser } =
    await identityWallet.createIdentity(
      "http://wallet.com/", // this is url that will be a part of auth bjj credential identifier
      {
        method: core.DidMethod.Iden3,
        blockchain: core.Blockchain.Polygon,
        networkId: core.NetworkId.Mumbai,
        rhsUrl,
      }
    );

  console.log("=============== user did ===============");
  console.log(userDID.toString());

  const { did: issuerDID, credential: issuerAuthBJJCredential } =
    await identityWallet.createIdentity(
      "http://wallet.com/", // this is url that will be a part of auth bjj credential identifier
      {
        method: core.DidMethod.Iden3,
        blockchain: core.Blockchain.Polygon,
        networkId: core.NetworkId.Mumbai,
        rhsUrl,
      }
    );

  const credentialRequest: CredentialRequest = {
    credentialSchema:
      "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json/KYCAgeCredential-v3.json",
    type: "KYCAgeCredential",
    credentialSubject: {
      id: userDID.toString(),
      birthday: 19960424,
      documentType: 99,
    },
    expiration: 12345678888,
  };
  const credential = await identityWallet.issueCredential(
    issuerDID,
    credentialRequest,
    "http://wallet.com/", // host url that will a prefix of credential identifier
    {
      withRHS: rhsUrl, // reverse hash service is used to check
    }
  );

  await dataStorage.credential.saveCredential(credential);

  console.log(
    "================= generate Iden3SparseMerkleTreeProof ======================="
  );

  const res = await identityWallet.addCredentialsToMerkleTree(
    [credential],
    issuerDID
  );

  console.log("================= push states to rhs ===================");

  await identityWallet.publishStateToRHS(issuerDID, rhsUrl);

  console.log("================= publish to blockchain ===================");

  const ethSigner = new ethers.Wallet(
    walletKey,
    (dataStorage.states as EthStateStorage).provider
  );
  const txId = await proofService.transitState(
    issuerDID,
    res.oldTreeState,
    true,
    dataStorage.states,
    ethSigner
  );
  console.log(txId);

  console.log(
    "================= generate credentialAtomicSigV2 ==================="
  );

  const proofReqSig: ZeroKnowledgeProofRequest = {
    id: 1,
    circuitId: CircuitId.AtomicQuerySigV2,
    optional: false,
    query: {
      allowedIssuers: ["*"],
      type: credentialRequest.type,
      context:
        "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
      credentialSubject: {
        documentType: {
          $eq: 99,
        },
      },
    },
  };

  let credsToChooseForZKPReq = await credentialWallet.findByQuery(
    proofReqSig.query
  );

  const { proof } = await proofService.generateProof(
    proofReqSig,
    userDID,
    credsToChooseForZKPReq[0]
  );

  const sigProofOk = await proofService.verifyProof(
    proof,
    CircuitId.AtomicQuerySigV2
  );
  console.log("valid: ", sigProofOk);

  console.log(
    "================= generate credentialAtomicMTPV2 ==================="
  );

  const credsWithIden3MTPProof =
    await identityWallet.generateIden3SparseMerkleTreeProof(
      issuerDID,
      res.credentials,
      txId
    );

  console.log(credsWithIden3MTPProof);
  credentialWallet.saveAll(credsWithIden3MTPProof);

  const proofReqMtp: ZeroKnowledgeProofRequest = {
    id: 1,
    circuitId: CircuitId.AtomicQueryMTPV2,
    optional: false,
    query: {
      allowedIssuers: ["*"],
      type: credentialRequest.type,
      context:
        "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
      credentialSubject: {
        birthday: {
          $lt: 20020101,
        },
      },
    },
  };
  credsToChooseForZKPReq = await credentialWallet.findByQuery(
    proofReqSig.query
  );
  const { proof: proofMTP } = await proofService.generateProof(
    proofReqMtp,
    userDID,
    credsToChooseForZKPReq[0]
  );
  console.log(JSON.stringify(proofMTP));
  const mtpProofOk = await proofService.verifyProof(
    proof,
    CircuitId.AtomicQueryMTPV2
  );
  console.log("valid: ", mtpProofOk);
  // const curve = await getCurveFromName('bn128');
  // curve.terminate();

  let credsToChooseForZKPReq2 = await credentialWallet.findByQuery(
    proofReqSig.query
  );

  const { proof: proof2 } = await proofService.generateProof(
    proofReqSig,
    userDID,
    credsToChooseForZKPReq2[0]
  );

  const sigProof2Ok = await proofService.verifyProof(
    proof2,
    CircuitId.AtomicQuerySigV2
  );
  console.log("valid: ", sigProof2Ok);
}

async function handleAuthRequest() {
  console.log("=============== handle auth request ===============");

  const dataStorage = initDataStorage();
  const credentialWallet = await initCredentialWallet(dataStorage);
  const identityWallet = await initIdentityWallet(
    dataStorage,
    credentialWallet
  );
  const circuitStorage = await initCircuitStorage();
  const proofService = await initProofService(
    identityWallet,
    credentialWallet,
    dataStorage.states,
    circuitStorage
  );

  const { did: userDID, credential: authBJJCredentialUser } =
    await identityWallet.createIdentity(
      "http://wallet.com/", // this is url that will be a part of auth bjj credential identifier
      {
        method: core.DidMethod.Iden3,
        blockchain: core.Blockchain.Polygon,
        networkId: core.NetworkId.Mumbai,
        rhsUrl,
      }
    );

  console.log("=============== user did ===============");
  console.log(userDID.toString());

  const { did: issuerDID, credential: issuerAuthBJJCredential } =
    await identityWallet.createIdentity(
      "http://wallet.com/", // this is url that will be a part of auth bjj credential identifier
      {
        method: core.DidMethod.Iden3,
        blockchain: core.Blockchain.Polygon,
        networkId: core.NetworkId.Mumbai,
        rhsUrl,
      }
    );

  const credentialRequest: CredentialRequest = {
    credentialSchema:
      "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json/KYCAgeCredential-v3.json",
    type: "KYCAgeCredential",
    credentialSubject: {
      id: userDID.toString(),
      birthday: 19960424,
      documentType: 99,
    },
    expiration: 12345678888,
  };
  const credential = await identityWallet.issueCredential(
    issuerDID,
    credentialRequest,
    "http://wallet.com/", // host url that will a prefix of credential identifier
    {
      withRHS: rhsUrl, // reverse hash service is used to check
    }
  );

  await dataStorage.credential.saveCredential(credential);

  console.log(
    "================= generate Iden3SparseMerkleTreeProof ======================="
  );

  const res = await identityWallet.addCredentialsToMerkleTree(
    [credential],
    issuerDID
  );

  console.log("================= push states to rhs ===================");

  await identityWallet.publishStateToRHS(issuerDID, rhsUrl);

  console.log("================= publish to blockchain ===================");

  const ethSigner = new ethers.Wallet(
    walletKey,
    (dataStorage.states as EthStateStorage).provider
  );
  const txId = await proofService.transitState(
    issuerDID,
    res.oldTreeState,
    true,
    dataStorage.states,
    ethSigner
  );
  console.log(txId);

  console.log(
    "================= generate credentialAtomicSigV2 ==================="
  );

  const proofReqSig: ZeroKnowledgeProofRequest = {
    id: 1,
    circuitId: CircuitId.AtomicQuerySigV2,
    optional: false,
    query: {
      allowedIssuers: ["*"],
      type: credentialRequest.type,
      context:
        "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
      credentialSubject: {
        documentType: {
          $eq: 99,
        },
      },
    },
  };

  console.log("=================  credential auth request ===================");

  var authRequest: AuthorizationRequestMessage = {
    id: "fe6354fe-3db2-48c2-a779-e39c2dda8d90",
    thid: "fe6354fe-3db2-48c2-a779-e39c2dda8d90",
    typ: PROTOCOL_CONSTANTS.MediaType.PlainMessage,
    from: issuerDID.toString(),
    type: PROTOCOL_CONSTANTS.PROTOCOL_MESSAGE_TYPE
      .AUTHORIZATION_REQUEST_MESSAGE_TYPE,
    body: {
      callbackUrl: "http://testcallback.com",
      message: "message to sign",
      scope: [proofReqSig],
      reason: "verify age",
    },
  };
  console.log(JSON.stringify(authRequest));

  const credsWithIden3MTPProof =
    await identityWallet.generateIden3SparseMerkleTreeProof(
      issuerDID,
      res.credentials,
      txId
    );

  console.log(credsWithIden3MTPProof);
  credentialWallet.saveAll(credsWithIden3MTPProof);


  var authRawRequest = new TextEncoder().encode(JSON.stringify(authRequest));

  // * on the user side */

  console.log("============== handle auth request ==============");
  const authV2Data = await circuitStorage.loadCircuitData(CircuitId.AuthV2);
  let pm = await initPackageManager(
    authV2Data,
    proofService.generateAuthV2Inputs.bind(proofService),
    proofService.verifyState.bind(proofService)
  );

  const authHandler = new AuthHandler(pm, proofService, credentialWallet);
  const authHandlerRequest =
    await authHandler.handleAuthorizationRequestForGenesisDID(
      userDID,
      authRawRequest
    );
    console.log(JSON.stringify(authHandlerRequest, null, 2));
}

async function handleAuthRequestWithProfiles() {
  console.log("=============== handle auth request with profiles ===============");

  const dataStorage = initDataStorage();
  const credentialWallet = await initCredentialWallet(dataStorage);
  const identityWallet = await initIdentityWallet(
    dataStorage,
    credentialWallet
  );
  const circuitStorage = await initCircuitStorage();
  const proofService = await initProofService(
    identityWallet,
    credentialWallet,
    dataStorage.states,
    circuitStorage
  );

  const { did: userDID, credential: authBJJCredentialUser } =
    await identityWallet.createIdentity(
      "http://wallet.com/", // this is url that will be a part of auth bjj credential identifier
      {
        method: core.DidMethod.Iden3,
        blockchain: core.Blockchain.Polygon,
        networkId: core.NetworkId.Mumbai,
        rhsUrl,
      }
    );

  console.log("=============== user did ===============");
  console.log(userDID.toString());

  const { did: issuerDID, credential: issuerAuthBJJCredential } =
    await identityWallet.createIdentity(
      "http://wallet.com/", // this is url that will be a part of auth bjj credential identifier
      {
        method: core.DidMethod.Iden3,
        blockchain: core.Blockchain.Polygon,
        networkId: core.NetworkId.Mumbai,
        rhsUrl,
      }
    );

   // credential is issued on the profile!
  const profileDID = await identityWallet.createProfile(userDID, 50, 'test verifier');

  const credentialRequest: CredentialRequest = {
    credentialSchema:
      "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json/KYCAgeCredential-v3.json",
    type: "KYCAgeCredential",
    credentialSubject: {
      id: profileDID.toString(),
      birthday: 19960424,
      documentType: 99,
    },
    expiration: 12345678888,
  };
  const credential = await identityWallet.issueCredential(
    issuerDID,
    credentialRequest,
    "http://wallet.com/", // host url that will a prefix of credential identifier
    {
      withRHS: rhsUrl, // reverse hash service is used to check
    }
  );

  await dataStorage.credential.saveCredential(credential);


  console.log(
    "================= generate credentialAtomicSigV2 ==================="
  );

  const proofReqSig: ZeroKnowledgeProofRequest = {
    id: 1,
    circuitId: CircuitId.AtomicQuerySigV2,
    optional: false,
    query: {
      allowedIssuers: ["*"],
      type: credentialRequest.type,
      context:
        "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
      credentialSubject: {
        documentType: {
          $eq: 99,
        },
      },
    },
  };

  console.log("=================  credential auth request ===================");

  var authRequest: AuthorizationRequestMessage = {
    id: "fe6354fe-3db2-48c2-a779-e39c2dda8d90",
    thid: "fe6354fe-3db2-48c2-a779-e39c2dda8d90",
    typ: PROTOCOL_CONSTANTS.MediaType.PlainMessage,
    from: issuerDID.toString(),
    type: PROTOCOL_CONSTANTS.PROTOCOL_MESSAGE_TYPE
      .AUTHORIZATION_REQUEST_MESSAGE_TYPE,
    body: {
      callbackUrl: "http://testcallback.com",
      message: "message to sign",
      scope: [proofReqSig],
      reason: "verify age",
    },
  };
  console.log(JSON.stringify(authRequest));



  var authRawRequest = new TextEncoder().encode(JSON.stringify(authRequest));

  // * on the user side */

  console.log("============== handle auth request ==============");
  const authV2Data = await circuitStorage.loadCircuitData(CircuitId.AuthV2);
  let pm = await initPackageManager(
    authV2Data,
    proofService.generateAuthV2Inputs.bind(proofService),
    proofService.verifyState.bind(proofService)
  );

  const authHandler = new AuthHandler(pm, proofService, credentialWallet);
   
    // for the flow when profiles are used it's important to know the nonces of profiles
    // for authentication profile and profile on which credential has been issued


    const authR = await authHandler.parseAuthorizationRequest(authRawRequest);

    // let's find credential for each request (emulation that we show it in the wallet ui)

    const reqCreds: ZKPRequestWithCredential[] = [];

    for (let index = 0; index < authR.body!.scope.length; index++) {
      const zkpReq = authR.body!.scope[index];

      const credsToChooseForZKPReq = await credentialWallet.findByQuery(zkpReq.query);

      // filter credentials for subjects that are profiles of identity

      const profiles = await dataStorage.identity.getProfilesByGenesisIdentifier(
        userDID.toString()
      );

      // finds all credentials that belongs to genesis identity or profiles derived from it
      const credsThatBelongToGenesisIdOrItsProfiles = credsToChooseForZKPReq.filter((cred) => {
        const credentialSubjectId = cred.credentialSubject['id'] as string; // credential subject
        return (
          credentialSubjectId == userDID.toString() ||
          profiles.some((p) => {
            return p.id === credentialSubjectId;
          })
        );
      });

      // you can show user credential that can be used for request (emulation - user choice)
      const chosenCredByUser = credsThatBelongToGenesisIdOrItsProfiles[0];

      // get profile nonce that was used as a part of subject in the credential
      const credentialSubjectProfileNonce =
        chosenCredByUser.credentialSubject['id'] === userDID.toString()
          ? 0
          : profiles.find((p) => {
              return p.id === chosenCredByUser.credentialSubject['id'];
            })!.nonce;
      console.log("credential profile nonce: ",credentialSubjectProfileNonce);      
      reqCreds.push({ req: zkpReq, credential: chosenCredByUser, credentialSubjectProfileNonce }); // profile nonce of credential subject
    }

    // you can create new profile here for auth or if you want to login with genesis set to 0.

    const authProfileNonce = 100;
    console.log("auth profile nonce: ",authProfileNonce);      


    const resp = await authHandler.generateAuthorizationResponse(
      userDID,
      authProfileNonce, // new profile for auth
      authR,
      reqCreds
    );

    console.log(resp);  
}

async function handleAuthRequestNoIssuerStateTransition() {
  console.log("=============== handle auth request no issuer state transition ===============");

  const dataStorage = initDataStorage();
  const credentialWallet = await initCredentialWallet(dataStorage);
  const identityWallet = await initIdentityWallet(
    dataStorage,
    credentialWallet
  );
  const circuitStorage = await initCircuitStorage();
  const proofService = await initProofService(
    identityWallet,
    credentialWallet,
    dataStorage.states,
    circuitStorage
  );

  const { did: userDID, credential: authBJJCredentialUser } =
    await identityWallet.createIdentity(
      "http://wallet.com/", // this is url that will be a part of auth bjj credential identifier
      {
        method: core.DidMethod.Iden3,
        blockchain: core.Blockchain.Polygon,
        networkId: core.NetworkId.Mumbai,
        rhsUrl,
      }
    );

  console.log("=============== user did ===============");
  console.log(userDID.toString());

  const { did: issuerDID, credential: issuerAuthBJJCredential } =
    await identityWallet.createIdentity(
      "http://wallet.com/", // this is url that will be a part of auth bjj credential identifier
      {
        method: core.DidMethod.Iden3,
        blockchain: core.Blockchain.Polygon,
        networkId: core.NetworkId.Mumbai,
        rhsUrl,
      }
    );

  const credentialRequest: CredentialRequest = {
    credentialSchema:
      "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json/KYCAgeCredential-v3.json",
    type: "KYCAgeCredential",
    credentialSubject: {
      id: userDID.toString(),
      birthday: 19960424,
      documentType: 99,
    },
    expiration: 12345678888,
  };
  const credential = await identityWallet.issueCredential(
    issuerDID,
    credentialRequest,
    "http://wallet.com/", // host url that will a prefix of credential identifier
    {
      withRHS: rhsUrl, // reverse hash service is used to check
    }
  );

  await dataStorage.credential.saveCredential(credential);

  console.log(
    "================= generate credentialAtomicSigV2 ==================="
  );

  const proofReqSig: ZeroKnowledgeProofRequest = {
    id: 1,
    circuitId: CircuitId.AtomicQuerySigV2,
    optional: false,
    query: {
      allowedIssuers: ["*"],
      type: credentialRequest.type,
      context:
        "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
      credentialSubject: {
        documentType: {
          $eq: 99,
        },
      },
    },
  };

  console.log("=================  credential auth request ===================");

  var authRequest: AuthorizationRequestMessage = {
    id: "fe6354fe-3db2-48c2-a779-e39c2dda8d90",
    thid: "fe6354fe-3db2-48c2-a779-e39c2dda8d90",
    typ: PROTOCOL_CONSTANTS.MediaType.PlainMessage,
    from: issuerDID.toString(),
    type: PROTOCOL_CONSTANTS.PROTOCOL_MESSAGE_TYPE
      .AUTHORIZATION_REQUEST_MESSAGE_TYPE,
    body: {
      callbackUrl: "http://testcallback.com",
      message: "message to sign",
      scope: [proofReqSig],
      reason: "verify age",
    },
  };
  console.log(JSON.stringify(authRequest));

  var authRawRequest = new TextEncoder().encode(JSON.stringify(authRequest));

  // * on the user side */

  console.log("============== handle auth request ==============");
  const authV2Data = await circuitStorage.loadCircuitData(CircuitId.AuthV2);
  let pm = await initPackageManager(
    authV2Data,
    proofService.generateAuthV2Inputs.bind(proofService),
    proofService.verifyState.bind(proofService)
  );

  const authHandler = new AuthHandler(pm, proofService, credentialWallet);
  const authHandlerRequest =
    await authHandler.handleAuthorizationRequestForGenesisDID(
      userDID,
      authRawRequest
    );
  console.log(JSON.stringify(authHandlerRequest, null, 2));
}

async function initPackageManager(
  circuitData: CircuitData,
  prepareFn: AuthDataPrepareFunc,
  stateVerificationFn: StateVerificationFunc
): Promise<IPackageManager> {
  const authInputsHandler = new DataPrepareHandlerFunc(prepareFn);

  const verificationFn = new VerificationHandlerFunc(stateVerificationFn);
  const mapKey =
    proving.provingMethodGroth16AuthV2Instance.methodAlg.toString();
  const verificationParamMap: Map<string, VerificationParams> = new Map([
    [
      mapKey,
      {
        key: circuitData.verificationKey,
        verificationFn,
      },
    ],
  ]);

  const provingParamMap: Map<string, ProvingParams> = new Map();
  provingParamMap.set(mapKey, {
    dataPreparer: authInputsHandler,
    provingKey: circuitData.provingKey,
    wasm: circuitData.wasm,
  });

  const mgr: IPackageManager = new PackageManager();
  const packer = new ZKPPacker(provingParamMap, verificationParamMap);
  const plainPacker = new PlainPacker();
  mgr.registerPackers([packer, plainPacker]);

  return mgr;
}

async function transitState() {
  console.log("=============== transit state ===============");

  const dataStorage = initDataStorage();
  const credentialWallet = await initCredentialWallet(dataStorage);
  const identityWallet = await initIdentityWallet(
    dataStorage,
    credentialWallet
  );
  const circuitStorage = await initCircuitStorage();
  const proofService = await initProofService(
    identityWallet,
    credentialWallet,
    dataStorage.states,
    circuitStorage
  );
  console.log(PROTOCOL_CONSTANTS);

  const { did: userDID, credential: authBJJCredentialUser } =
    await identityWallet.createIdentity(
      "http://wallet.com/", // this is url that will be a part of auth bjj credential identifier
      {
        method: core.DidMethod.Iden3,
        blockchain: core.Blockchain.Polygon,
        networkId: core.NetworkId.Mumbai,
        rhsUrl,
      }
    );

  console.log("=============== user did ===============");
  console.log(userDID.toString());

  const { did: issuerDID, credential: issuerAuthBJJCredential } =
    await identityWallet.createIdentity(
      "http://wallet.com/", // this is url that will be a part of auth bjj credential identifier
      {
        method: core.DidMethod.Iden3,
        blockchain: core.Blockchain.Polygon,
        networkId: core.NetworkId.Mumbai,
        rhsUrl,
      }
    );

  const credentialRequest: CredentialRequest = {
    credentialSchema:
      "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json/KYCAgeCredential-v3.json",
    type: "KYCAgeCredential",
    credentialSubject: {
      id: userDID.toString(),
      birthday: 19960424,
      documentType: 99,
    },
    expiration: 12345678888,
  };
  const credential = await identityWallet.issueCredential(
    issuerDID,
    credentialRequest,
    "http://wallet.com/", // host url that will a prefix of credential identifier
    {
      withRHS: rhsUrl, // reverse hash service is used to check
    }
  );

  await dataStorage.credential.saveCredential(credential);

  console.log(
    "================= generate Iden3SparseMerkleTreeProof ======================="
  );

  const res = await identityWallet.addCredentialsToMerkleTree(
    [credential],
    issuerDID
  );

  console.log("================= push states to rhs ===================");

  await identityWallet.publishStateToRHS(issuerDID, rhsUrl);

  console.log("================= publish to blockchain ===================");

  const ethSigner = new ethers.Wallet(
    walletKey,
    (dataStorage.states as EthStateStorage).provider
  );
  const txId = await proofService.transitState(
    issuerDID,
    res.oldTreeState,
    true,
    dataStorage.states,
    ethSigner
  );
  console.log(txId);
}

async function main() {
  await identityCreation();
  await issueCredential();
  await transitState();
  await generateProofs();
  
  await handleAuthRequest();

  await handleAuthRequestWithProfiles();


  await handleAuthRequestNoIssuerStateTransition();
}
(async function () {
  await main();
})();
