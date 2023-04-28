/**
 * Handle authorization request: flow without usage of profiles.
 *
 * Same as handle-auth.ts but with some extra comments, logging and other clarifications.
 *
 * @see https://0xpolygonid.github.io/js-sdk-tutorials/docs/tutorial-basics/auth-handler
 */

import { proving } from "@iden3/js-jwz";
import {
  AuthDataPrepareFunc,
  AuthHandler,
  AuthorizationRequestMessage,
  BjjProvider,
  CircuitData,
  CircuitId,
  CircuitStorage,
  core,
  CredentialRequest,
  CredentialStatusType,
  CredentialStorage,
  CredentialWallet,
  DataPrepareHandlerFunc,
  defaultEthConnectionConfig,
  EthConnectionConfig,
  EthStateStorage,
  FSKeyLoader,
  ICircuitStorage,
  ICredentialWallet,
  IDataStorage,
  Identity,
  IdentityStorage,
  IdentityWallet,
  IIdentityWallet,
  InMemoryDataSource,
  InMemoryMerkleTreeStorage,
  InMemoryPrivateKeyStore,
  IPackageManager,
  IStateStorage,
  KMS,
  KmsKeyType,
  PackageManager,
  PlainPacker,
  Profile,
  ProofService,
  PROTOCOL_CONSTANTS,
  ProvingParams,
  StateVerificationFunc,
  VerificationHandlerFunc,
  VerificationParams,
  W3CCredential,
  ZeroKnowledgeProofRequest,
  ZKPPacker,
} from "@0xpolygonid/js-sdk";
import { ethers } from "ethers";
import path from "path";

import {
  rhsUrl,
  rpcUrl,
  contractAddress,
  walletKey,
  circuitsFolder,
} from "./config";

function initDataStorage(): IDataStorage {
  console.log(contractAddress);
  
  const conf: EthConnectionConfig = {
    ...defaultEthConnectionConfig,
    contractAddress,
    url: rpcUrl,
  };

  console.log(conf);
  

  const dataStorage = {
    credential: new CredentialStorage(new InMemoryDataSource<W3CCredential>()),
    identity: new IdentityStorage(
      new InMemoryDataSource<Identity>(),
      new InMemoryDataSource<Profile>()
    ),
    mt: new InMemoryMerkleTreeStorage(40),
    states: new EthStateStorage(conf),
  };

  return dataStorage;
}

async function initCredentialWallet(
  dataStorage: IDataStorage
): Promise<CredentialWallet> {
  return new CredentialWallet(dataStorage);
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

async function initCircuitStorage(): Promise<ICircuitStorage> {
  const circuitStorage = new CircuitStorage(
    new InMemoryDataSource<CircuitData>()
  );

  const loader = new FSKeyLoader(path.join(__dirname, circuitsFolder));

  await circuitStorage.saveCircuitData(CircuitId.AuthV2, {
    circuitId: CircuitId.AuthV2,
    wasm: await loader.load(`${CircuitId.AuthV2}/circuit.wasm`),
    provingKey: await loader.load(`${CircuitId.AuthV2}/circuit_final.zkey`),
    verificationKey: await loader.load(
      `${CircuitId.AuthV2}/verification_key.json`
    ),
  });

  await circuitStorage.saveCircuitData(CircuitId.AtomicQuerySigV2, {
    circuitId: CircuitId.AtomicQuerySigV2,
    wasm: await loader.load(`${CircuitId.AtomicQuerySigV2}/circuit.wasm`),
    provingKey: await loader.load(
      `${CircuitId.AtomicQuerySigV2}/circuit_final.zkey`
    ),
    verificationKey: await loader.load(
      `${CircuitId.AtomicQuerySigV2}/verification_key.json`
    ),
  });

  await circuitStorage.saveCircuitData(CircuitId.StateTransition, {
    circuitId: CircuitId.StateTransition,
    wasm: await loader.load(`${CircuitId.StateTransition}/circuit.wasm`),
    provingKey: await loader.load(
      `${CircuitId.StateTransition}/circuit_final.zkey`
    ),
    verificationKey: await loader.load(
      `${CircuitId.StateTransition}/verification_key.json`
    ),
  });

  await circuitStorage.saveCircuitData(CircuitId.AtomicQueryMTPV2, {
    circuitId: CircuitId.AtomicQueryMTPV2,
    wasm: await loader.load(`${CircuitId.AtomicQueryMTPV2}/circuit.wasm`),
    provingKey: await loader.load(
      `${CircuitId.AtomicQueryMTPV2}/circuit_final.zkey`
    ),
    verificationKey: await loader.load(
      `${CircuitId.AtomicQueryMTPV2}/verification_key.json`
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

const className = (obj: object) => obj.constructor.name;

const json = (obj: object, indent = 2) => JSON.stringify(obj, null, indent);

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
      // this is url that will be a part of auth bjj credential identifier
      {
        method: core.DidMethod.Iden3,
        blockchain: core.Blockchain.Polygon,
        networkId: core.NetworkId.Mumbai,
        revocationOpts: {
          type: CredentialStatusType.Iden3ReverseSparseMerkleTreeProof,
          baseUrl: rhsUrl,
        },
      }
    );

  console.log("\n=============== user did and auth credential===============");
  console.log(className(userDID), userDID.toString());
  console.log(className(authBJJCredentialUser), json(authBJJCredentialUser));

  const { did: issuerDID, credential: issuerAuthBJJCredential } =
    await identityWallet.createIdentity({
      method: core.DidMethod.Iden3,
      blockchain: core.Blockchain.Polygon,
      networkId: core.NetworkId.Mumbai,
      revocationOpts: {
        type: CredentialStatusType.Iden3ReverseSparseMerkleTreeProof,
        baseUrl: rhsUrl,
      },
    });

  console.log(
    "\n=============== issuer did and auth credential ==============="
  );
  console.log(className(issuerDID), issuerDID.toString());
  console.log(
    className(issuerAuthBJJCredential),
    json(issuerAuthBJJCredential)
  );

  console.log(
    "================= transition for issuer genesis state ======================="
  );

  const res = await identityWallet.addCredentialsToMerkleTree([], issuerDID);
  console.log("old tree state (hashes):", {
    claimsRoot: res.oldTreeState.claimsRoot.hex(),
    revocationRoot: res.oldTreeState.revocationRoot.hex(),
    rootOfRoots: res.oldTreeState.rootOfRoots.hex(),
    state: res.oldTreeState.state.hex(),
  });
  console.log("new tree state (hashes):", {
    claimsRoot: res.newTreeState.claimsRoot.hex(),
    revocationRoot: res.newTreeState.revocationRoot.hex(),
    rootOfRoots: res.newTreeState.rootOfRoots.hex(),
    state: res.newTreeState.state.hex(),
  });

  console.log(
    "================= push updated issuer state to RHS (Reverse Hash Service) ==================="
  );

  await identityWallet.publishStateToRHS(issuerDID, rhsUrl);

  console.log(
    "================= publish issuer state to blockchain, with state transition proof ==================="
  );

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
  console.log("transaction ID:", txId);

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
    revocationOpts: {
      type: CredentialStatusType.Iden3ReverseSparseMerkleTreeProof,
      baseUrl: rhsUrl,
    },
  };

  console.log(
    "\n=============== credential request for issuer to sign ==============="
  );
  console.log(json(credentialRequest));

  const credential = await identityWallet.issueCredential(
    issuerDID,
    credentialRequest
  );

  console.log("\n=============== issued credential, signed ===============");
  console.log(className(credential), json(credential));

  dataStorage.credential.saveCredential(credential);

  console.log(
    "================= add credential to issuer ID wallet claims tree ======================="
  );

  const res2 = await identityWallet.addCredentialsToMerkleTree(
    [credential],
    issuerDID
  );
  console.log("old tree state (hashes):", {
    claimsRoot: res2.oldTreeState.claimsRoot.hex(),
    revocationRoot: res2.oldTreeState.revocationRoot.hex(),
    rootOfRoots: res2.oldTreeState.rootOfRoots.hex(),
    state: res2.oldTreeState.state.hex(),
  });
  console.log("new tree state (hashes):", {
    claimsRoot: res2.newTreeState.claimsRoot.hex(),
    revocationRoot: res2.newTreeState.revocationRoot.hex(),
    rootOfRoots: res2.newTreeState.rootOfRoots.hex(),
    state: res2.newTreeState.state.hex(),
  });

  console.log(
    "================= generate Iden3SparseMerkleTreeProof ======================="
  );

  const credsWithIden3MTPProof =
    await identityWallet.generateIden3SparseMerkleTreeProof(
      issuerDID,
      res2.credentials,
      "" // we have no transaction ID since we did not update ID state after issuing credential
    );

  credentialWallet.saveAll(credsWithIden3MTPProof);

  const credWithIden3MTP = credsWithIden3MTPProof[0];
  for (let proof of credWithIden3MTP.proof as any[]) {
    if (proof.type === "Iden3SparseMerkleProof") {
      proof.mtp.siblings = proof.mtp.siblings.map((h: any) => h.hex());
    }
  }
  console.log(className(credWithIden3MTP), json(credWithIden3MTP));

  console.log(
    "================= generate credentialAtomicSigV2 proof request ==================="
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
        birthday: {
          $lt: 20020101,
        },
      },
    },
  };

  console.log(
    "=================  credential auth request message ==================="
  );

  const authRequest: AuthorizationRequestMessage = {
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
  console.log(json(authRequest));

  const authRawRequest = new TextEncoder().encode(json(authRequest));

  // * on the user side */

  console.log("\n============== user handles auth request ==============");

  const authV2Data = await circuitStorage.loadCircuitData(CircuitId.AuthV2);
  const pm = await initPackageManager(
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
  console.log(json(authHandlerRequest));
}

handleAuthRequest()
  .then(() => {
    process.exit(0);
  })
  .catch((err) => {
    console.error("ERROR:", err);
    process.exit(1);
  });
