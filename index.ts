/* eslint-disable @typescript-eslint/no-unused-vars */
/* eslint-disable no-console */
import {
  EthStateStorage,
  CredentialRequest,
  CircuitId,
  ZeroKnowledgeProofRequest,
  AuthorizationRequestMessage,
  PROTOCOL_CONSTANTS,
  AuthHandler,
  core,
  CredentialStatusType,
  IdentityCreationOptions
} from '@0xpolygonid/js-sdk';

import {
  initInMemoryDataStorageAndWallets,
  initCircuitStorage,
  initProofService,
  initPackageManager,
  initMongoDataStorageAndWallets
} from './walletSetup';

import { ethers } from 'ethers';
import dotenv from 'dotenv';
import { generateRequestData } from './request';
dotenv.config();

const rhsUrl = process.env.RHS_URL as string;
const walletKey = process.env.WALLET_KEY as string;

const defaultNetworkConnection = {
  rpcUrl: process.env.RPC_URL as string,
  contractAddress: process.env.CONTRACT_ADDRESS as string
};

export const defaultIdentityCreationOptions: IdentityCreationOptions = {
  method: core.DidMethod.Iden3,
  blockchain: core.Blockchain.Polygon,
  networkId: core.NetworkId.Mumbai,
  revocationOpts: {
    type: CredentialStatusType.Iden3ReverseSparseMerkleTreeProof,
    id: rhsUrl
  }
};

function createKYCAgeCredential(did: core.DID) {
  const credentialRequest: CredentialRequest = {
    credentialSchema:
      'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json/KYCAgeCredential-v3.json',
    type: 'KYCAgeCredential',
    credentialSubject: {
      id: did.string(),
      birthday: 19960424,
      documentType: 99
    },
    expiration: 12345678888,
    revocationOpts: {
      type: CredentialStatusType.Iden3ReverseSparseMerkleTreeProof,
      id: rhsUrl
    }
  };
  return credentialRequest;
}

function createKYCAgeCredentialRequest(
  circuitId: CircuitId,
  credentialRequest: CredentialRequest
): ZeroKnowledgeProofRequest {
  const proofReqSig: ZeroKnowledgeProofRequest = {
    id: 1,
    circuitId: CircuitId.AtomicQuerySigV2,
    optional: false,
    query: {
      allowedIssuers: ['*'],
      type: credentialRequest.type,
      context:
        'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld',
      credentialSubject: {
        documentType: {
          $eq: 99
        }
      }
    }
  };

  const proofReqMtp: ZeroKnowledgeProofRequest = {
    id: 1,
    circuitId: CircuitId.AtomicQueryMTPV2,
    optional: false,
    query: {
      allowedIssuers: ['*'],
      type: credentialRequest.type,
      context:
        'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld',
      credentialSubject: {
        birthday: {
          $lt: 20020101
        }
      }
    }
  };

  switch (circuitId) {
    case CircuitId.AtomicQuerySigV2:
      return proofReqSig;
    case CircuitId.AtomicQueryMTPV2:
      return proofReqMtp;
    default:
      return proofReqSig;
  }
}

async function identityCreation() {
  console.log('=============== key creation ===============');

  const { identityWallet } = await initInMemoryDataStorageAndWallets(defaultNetworkConnection);
  const { did, credential } = await identityWallet.createIdentity(defaultIdentityCreationOptions);

  console.log('=============== did ===============');
  console.log(did.string());
  console.log('=============== Auth BJJ credential ===============');
  console.log(JSON.stringify(credential));
}

async function issueCredential() {
  console.log('=============== issue credential ===============');

  const { dataStorage, identityWallet } = await initInMemoryDataStorageAndWallets(
    defaultNetworkConnection
  );

  const { did: userDID, credential: authBJJCredentialUser } = await identityWallet.createIdentity(
    defaultIdentityCreationOptions
  );

  console.log('=============== user did ===============');
  console.log(userDID.string());

  const { did: issuerDID, credential: issuerAuthBJJCredential } =
    await identityWallet.createIdentity(defaultIdentityCreationOptions);

  const credentialRequest = createKYCAgeCredential(userDID);
  const credential = await identityWallet.issueCredential(issuerDID, credentialRequest);

  console.log('===============  credential ===============');
  console.log(JSON.stringify(credential));

  await dataStorage.credential.saveCredential(credential);
}

async function transitState() {
  console.log('=============== transit state ===============');

  const { dataStorage, credentialWallet, identityWallet } = await initInMemoryDataStorageAndWallets(
    defaultNetworkConnection
  );

  const circuitStorage = await initCircuitStorage();
  const proofService = await initProofService(
    identityWallet,
    credentialWallet,
    dataStorage.states,
    circuitStorage
  );

  const { did: userDID, credential: authBJJCredentialUser } = await identityWallet.createIdentity(
    defaultIdentityCreationOptions
  );

  console.log('=============== user did ===============');
  console.log(userDID.string());

  const { did: issuerDID, credential: issuerAuthBJJCredential } =
    await identityWallet.createIdentity(defaultIdentityCreationOptions);


  console.log('=============== issuerDID did ===============');
  console.log(issuerDID.string());

  const credentialRequest = createKYCAgeCredential(userDID);
  const credential = await identityWallet.issueCredential(issuerDID, credentialRequest);

  await dataStorage.credential.saveCredential(credential);

  console.log('================= generate Iden3SparseMerkleTreeProof =======================');

  const res = await identityWallet.addCredentialsToMerkleTree([credential], issuerDID);

  console.log('================= push states to rhs ===================');

  await identityWallet.publishStateToRHS(issuerDID, rhsUrl);

  console.log('================= publish to blockchain ===================');

  const ethSigner = new ethers.Wallet(walletKey, (dataStorage.states as EthStateStorage).provider);
  const txId = await proofService.transitState(
    issuerDID,
    res.oldTreeState,
    true,
    dataStorage.states,
    ethSigner
  );
  console.log(txId);
}

// async function transitStateThirdPartyDID() {
//   console.log('=============== THIRD PARTY DID: transit state  ===============');
//   core.registerDidMethodNetwork({
//     method: 'thirdparty',
//     methodByte: 0b1000_0001,
//     blockchain: 'linea',
//     network: 'test',
//     networkFlag: 0b01000000 | 0b00000001,
//     chainId: 59140
//   });

//   core.registerDidMethodNetwork({
//     method: 'iden3',
//     blockchain: 'linea',
//     network: 'test',
//     networkFlag: 0b11000000 | 0b00000011
//   });

//   const { dataStorage, credentialWallet, identityWallet } = await initInMemoryDataStorageAndWallets(
//     {
//       rpcUrl: process.env.THIRD_PARTY_RPC_URL as string,
//       contractAddress: process.env.THIRD_PARTY_CONTRACT_ADDRESS as string
//     }
//   );

//   console.log(process.env.THIRD_PARTY_RPC_URL, process.env.THIRD_PARTY_CONTRACT_ADDRESS);

//   const circuitStorage = await initCircuitStorage();
//   const proofService = await initProofService(
//     identityWallet,
//     credentialWallet,
//     dataStorage.states,
//     circuitStorage
//   );

//   const method = core.DidMethod.thirdparty;
//   const blockchain = core.Blockchain.linea;
//   const networkId = core.NetworkId.test;
//   const { did: userDID } = await identityWallet.createIdentity({
//     method,
//     blockchain,
//     networkId,
//     revocationOpts: {
//       type: CredentialStatusType.Iden3ReverseSparseMerkleTreeProof,
//       id: rhsUrl
//     }
//   });

//   console.log('=============== third party: user did ===============');
//   console.log(userDID.string());

//   const { did: issuerDID } = await identityWallet.createIdentity({
//     method: core.DidMethod.Iden3,
//     blockchain: core.Blockchain.linea,
//     networkId: core.NetworkId.test,
//     revocationOpts: {
//       type: CredentialStatusType.Iden3ReverseSparseMerkleTreeProof,
//       id: rhsUrl
//     }
//   });
//   console.log('=============== third party: issuer did ===============');
//   console.log(issuerDID.string());

//   const credentialRequest = createKYCAgeCredential(userDID);
//   const credential = await identityWallet.issueCredential(issuerDID, credentialRequest);

//   await dataStorage.credential.saveCredential(credential);

//   console.log(
//     '================= third party: generate Iden3SparseMerkleTreeProof ======================='
//   );

//   const res = await identityWallet.addCredentialsToMerkleTree([credential], issuerDID);

//   console.log('================= third party: push states to rhs ===================');

//   await identityWallet.publishStateToRHS(issuerDID, rhsUrl);

//   console.log('================= publish to blockchain ===================');

//   const ethSigner = new ethers.Wallet(
//     process.env.THIRD_PARTY_WALLET_KEY as string,
//     (dataStorage.states as EthStateStorage).provider
//   );
//   const txId = await proofService.transitState(
//     issuerDID,
//     res.oldTreeState,
//     true,
//     dataStorage.states,
//     ethSigner
//   );
//   console.log(txId);
// }

async function generateProofs(useMongoStore = false) {
  console.log('=============== generate proofs ===============');

  let dataStorage, credentialWallet, identityWallet;
  if (useMongoStore) {
    ({ dataStorage, credentialWallet, identityWallet } = await initMongoDataStorageAndWallets(
      defaultNetworkConnection
    ));
  } else {
    ({ dataStorage, credentialWallet, identityWallet } = await initInMemoryDataStorageAndWallets(
      defaultNetworkConnection
    ));
  }

  const circuitStorage = await initCircuitStorage();
  const proofService = await initProofService(
    identityWallet,
    credentialWallet,
    dataStorage.states,
    circuitStorage
  );

  const { did: userDID, credential: authBJJCredentialUser } = await identityWallet.createIdentity(
    defaultIdentityCreationOptions
  );

  console.log('=============== user did ===============');
  console.log(userDID.string());

  const { did: issuerDID, credential: issuerAuthBJJCredential } =
    await identityWallet.createIdentity(defaultIdentityCreationOptions);

  const credentialRequest = createKYCAgeCredential(userDID);
  const credential = await identityWallet.issueCredential(issuerDID, credentialRequest);

  await dataStorage.credential.saveCredential(credential);

  console.log('================= generate Iden3SparseMerkleTreeProof =======================');

  const res = await identityWallet.addCredentialsToMerkleTree([credential], issuerDID);

  console.log('================= push states to rhs ===================');

  await identityWallet.publishStateToRHS(issuerDID, rhsUrl);

  console.log('================= publish to blockchain ===================');

  const ethSigner = new ethers.Wallet(walletKey, (dataStorage.states as EthStateStorage).provider);
  const txId = await proofService.transitState(
    issuerDID,
    res.oldTreeState,
    true,
    dataStorage.states,
    ethSigner
  );
  console.log(txId);

  console.log('================= generate credentialAtomicSigV2 ===================');

  const proofReqSig: ZeroKnowledgeProofRequest = createKYCAgeCredentialRequest(
    CircuitId.AtomicQuerySigV2,
    credentialRequest
  );

  const { proof, pub_signals } = await proofService.generateProof(proofReqSig, userDID);

  const sigProofOk = await proofService.verifyProof(
    { proof, pub_signals },
    CircuitId.AtomicQuerySigV2
  );
  console.log('valid: ', sigProofOk);

  console.log('================= generate credentialAtomicMTPV2 ===================');

  const credsWithIden3MTPProof = await identityWallet.generateIden3SparseMerkleTreeProof(
    issuerDID,
    res.credentials,
    txId
  );

  console.log(credsWithIden3MTPProof);
  await credentialWallet.saveAll(credsWithIden3MTPProof);

  const proofReqMtp: ZeroKnowledgeProofRequest = createKYCAgeCredentialRequest(
    CircuitId.AtomicQueryMTPV2,
    credentialRequest
  );

  const { proof: proofMTP } = await proofService.generateProof(proofReqMtp, userDID);

  console.log(JSON.stringify(proofMTP));
  const mtpProofOk = await proofService.verifyProof(
    { proof, pub_signals },
    CircuitId.AtomicQueryMTPV2
  );
  console.log('valid: ', mtpProofOk);

  const { proof: proof2, pub_signals: pub_signals2 } = await proofService.generateProof(
    proofReqSig,
    userDID
  );

  const sigProof2Ok = await proofService.verifyProof(
    { proof: proof2, pub_signals: pub_signals2 },
    CircuitId.AtomicQuerySigV2
  );
  console.log('valid: ', sigProof2Ok);
}

async function handleAuthRequest(useMongoStore = false) {
  console.log('=============== handle auth request ===============');

  let dataStorage, credentialWallet, identityWallet;
  if (useMongoStore) {
    ({ dataStorage, credentialWallet, identityWallet } = await initMongoDataStorageAndWallets(
      defaultNetworkConnection
    ));
  } else {
    ({ dataStorage, credentialWallet, identityWallet } = await initInMemoryDataStorageAndWallets(
      defaultNetworkConnection
    ));
  }

  const circuitStorage = await initCircuitStorage();
  const proofService = await initProofService(
    identityWallet,
    credentialWallet,
    dataStorage.states,
    circuitStorage
  );

  const { did: userDID, credential: authBJJCredentialUser } = await identityWallet.createIdentity(
    defaultIdentityCreationOptions
  );

  console.log('=============== user did ===============');
  console.log(userDID.string());

  const { did: issuerDID, credential: issuerAuthBJJCredential } =
    await identityWallet.createIdentity(defaultIdentityCreationOptions);

  const credentialRequest = createKYCAgeCredential(userDID);
  const credential = await identityWallet.issueCredential(issuerDID, credentialRequest);

  await dataStorage.credential.saveCredential(credential);

  console.log('================= generate Iden3SparseMerkleTreeProof =======================');

  const res = await identityWallet.addCredentialsToMerkleTree([credential], issuerDID);

  console.log('================= push states to rhs ===================');

  await identityWallet.publishStateToRHS(issuerDID, rhsUrl);

  console.log('================= publish to blockchain ===================');

  const ethSigner = new ethers.Wallet(walletKey, (dataStorage.states as EthStateStorage).provider);
  const txId = await proofService.transitState(
    issuerDID,
    res.oldTreeState,
    true,
    dataStorage.states,
    ethSigner
  );
  console.log(txId);

  console.log('================= generate credentialAtomicSigV2 ===================');

  const proofReqSig: ZeroKnowledgeProofRequest = createKYCAgeCredentialRequest(
    CircuitId.AtomicQuerySigV2,
    credentialRequest
  );

  console.log('=================  credential auth request ===================');

  const authRequest: AuthorizationRequestMessage = {
    id: 'fe6354fe-3db2-48c2-a779-e39c2dda8d90',
    thid: 'fe6354fe-3db2-48c2-a779-e39c2dda8d90',
    typ: PROTOCOL_CONSTANTS.MediaType.PlainMessage,
    from: issuerDID.string(),
    type: PROTOCOL_CONSTANTS.PROTOCOL_MESSAGE_TYPE.AUTHORIZATION_REQUEST_MESSAGE_TYPE,
    body: {
      callbackUrl: 'http://testcallback.com',
      message: 'message to sign',
      scope: [proofReqSig],
      reason: 'verify age'
    }
  };
  console.log(JSON.stringify(authRequest));

  const credsWithIden3MTPProof = await identityWallet.generateIden3SparseMerkleTreeProof(
    issuerDID,
    res.credentials,
    txId
  );

  console.log(credsWithIden3MTPProof);
  await credentialWallet.saveAll(credsWithIden3MTPProof);

  const authRawRequest = new TextEncoder().encode(JSON.stringify(authRequest));

  // * on the user side */

  console.log('============== handle auth request ==============');
  const authV2Data = await circuitStorage.loadCircuitData(CircuitId.AuthV2);
  const pm = await initPackageManager(
    authV2Data,
    proofService.generateAuthV2Inputs.bind(proofService),
    proofService.verifyState.bind(proofService)
  );

  const authHandler = new AuthHandler(pm, proofService);
  const authHandlerRequest = await authHandler.handleAuthorizationRequest(userDID, authRawRequest);
  console.log(JSON.stringify(authHandlerRequest, null, 2));
}

async function handleAuthRequestWithProfiles() {
  console.log('=============== handle auth request with profiles ===============');

  const { dataStorage, credentialWallet, identityWallet } = await initInMemoryDataStorageAndWallets(
    defaultNetworkConnection
  );

  const circuitStorage = await initCircuitStorage();
  const proofService = await initProofService(
    identityWallet,
    credentialWallet,
    dataStorage.states,
    circuitStorage
  );

  const { did: userDID, credential: authBJJCredentialUser } = await identityWallet.createIdentity(
    defaultIdentityCreationOptions
  );

  console.log('=============== user did ===============');
  console.log(userDID.string());

  const { did: issuerDID, credential: issuerAuthBJJCredential } =
    await identityWallet.createIdentity(defaultIdentityCreationOptions);

  // credential is issued on the profile!
  const profileDID = await identityWallet.createProfile(userDID, 50, issuerDID.string());

  const credentialRequest = createKYCAgeCredential(profileDID);
  const credential = await identityWallet.issueCredential(issuerDID, credentialRequest);

  await dataStorage.credential.saveCredential(credential);

  console.log('================= generate credentialAtomicSigV2 ===================');

  const proofReqSig: ZeroKnowledgeProofRequest = createKYCAgeCredentialRequest(
    CircuitId.AtomicQuerySigV2,
    credentialRequest
  );

  console.log('=================  credential auth request ===================');
  const verifierDID = 'did:example:123#JUvpllMEYUZ2joO59UNui_XYDqxVqiFLLAJ8klWuPBw';

  const authRequest: AuthorizationRequestMessage = {
    id: 'fe6354fe-3db2-48c2-a779-e39c2dda8d90',
    thid: 'fe6354fe-3db2-48c2-a779-e39c2dda8d90',
    typ: PROTOCOL_CONSTANTS.MediaType.PlainMessage,
    from: verifierDID,
    type: PROTOCOL_CONSTANTS.PROTOCOL_MESSAGE_TYPE.AUTHORIZATION_REQUEST_MESSAGE_TYPE,
    body: {
      callbackUrl: 'http://testcallback.com',
      message: 'message to sign',
      scope: [proofReqSig],
      reason: 'verify age'
    }
  };
  console.log(JSON.stringify(authRequest));

  const authRawRequest = new TextEncoder().encode(JSON.stringify(authRequest));

  // * on the user side */

  console.log('============== handle auth request ==============');
  const authV2Data = await circuitStorage.loadCircuitData(CircuitId.AuthV2);
  const pm = await initPackageManager(
    authV2Data,
    proofService.generateAuthV2Inputs.bind(proofService),
    proofService.verifyState.bind(proofService)
  );

  const authHandler = new AuthHandler(pm, proofService);

  const authProfile = await identityWallet.getProfileByVerifier(authRequest.from);

  // let's check that we didn't create profile for verifier
  const authProfileDID = authProfile
    ? core.DID.parse(authProfile.id)
    : await identityWallet.createProfile(userDID, 100, authRequest.from);

  const resp = await authHandler.handleAuthorizationRequest(authProfileDID, authRawRequest);

  console.log(resp);
}

async function handleAuthRequestNoIssuerStateTransition() {
  console.log('=============== handle auth request no issuer state transition ===============');

  const { dataStorage, credentialWallet, identityWallet } = await initInMemoryDataStorageAndWallets(
    defaultNetworkConnection
  );

  const circuitStorage = await initCircuitStorage();
  const proofService = await initProofService(
    identityWallet,
    credentialWallet,
    dataStorage.states,
    circuitStorage
  );

  const { did: userDID, credential: authBJJCredentialUser } = await identityWallet.createIdentity(
    defaultIdentityCreationOptions
  );

  console.log('=============== user did ===============');
  console.log(userDID.string());

  const { did: issuerDID, credential: issuerAuthBJJCredential } =
    await identityWallet.createIdentity(defaultIdentityCreationOptions);

  const credentialRequest = createKYCAgeCredential(userDID);
  const credential = await identityWallet.issueCredential(issuerDID, credentialRequest);

  await dataStorage.credential.saveCredential(credential);

  console.log('================= generate credentialAtomicSigV2 ===================');

  const proofReqSig: ZeroKnowledgeProofRequest = createKYCAgeCredentialRequest(
    CircuitId.AtomicQuerySigV2,
    credentialRequest
  );

  console.log('=================  credential auth request ===================');

  const authRequest: AuthorizationRequestMessage = {
    id: 'fe6354fe-3db2-48c2-a779-e39c2dda8d90',
    thid: 'fe6354fe-3db2-48c2-a779-e39c2dda8d90',
    typ: PROTOCOL_CONSTANTS.MediaType.PlainMessage,
    from: issuerDID.string(),
    type: PROTOCOL_CONSTANTS.PROTOCOL_MESSAGE_TYPE.AUTHORIZATION_REQUEST_MESSAGE_TYPE,
    body: {
      callbackUrl: 'http://testcallback.com',
      message: 'message to sign',
      scope: [proofReqSig],
      reason: 'verify age'
    }
  };
  console.log(JSON.stringify(authRequest));

  const authRawRequest = new TextEncoder().encode(JSON.stringify(authRequest));

  // * on the user side */

  console.log('============== handle auth request ==============');
  const authV2Data = await circuitStorage.loadCircuitData(CircuitId.AuthV2);
  const pm = await initPackageManager(
    authV2Data,
    proofService.generateAuthV2Inputs.bind(proofService),
    proofService.verifyState.bind(proofService)
  );

  const authHandler = new AuthHandler(pm, proofService);
  const authHandlerRequest = await authHandler.handleAuthorizationRequest(userDID, authRawRequest);
  console.log(JSON.stringify(authHandlerRequest, null, 2));
}

async function main(choice: string) {
  switch (choice) {
    case 'identityCreation':
      await identityCreation();
      break;
    case 'issueCredential':
      await issueCredential();
      break;
    case 'transitState':
      await transitState();
      break;
    case 'generateProofs':
      await generateProofs();
      break;
    case 'handleAuthRequest':
      await handleAuthRequest();
      break;
    case 'handleAuthRequestWithProfiles':
      await handleAuthRequestWithProfiles();
      break;
    case 'handleAuthRequestNoIssuerStateTransition':
      await handleAuthRequestNoIssuerStateTransition();
      break;
    case 'generateRequestData':
      await generateRequestData();
      break;
    case 'generateProofsMongo':
      await generateProofs(true);
      break;
    case 'handleAuthRequestMongo':
      await handleAuthRequest(true);
      break;
    case 'transitStateThirdPartyDID':
      // await transitStateThirdPartyDID();
      break;

    default:
      // default run all
      await identityCreation();
      await issueCredential();
      await transitState();
      // await transitStateThirdPartyDID();
      await generateProofs();
      await handleAuthRequest();
      await handleAuthRequestWithProfiles();
      await handleAuthRequestNoIssuerStateTransition();
      await generateRequestData();
      await generateProofs(true);
      await handleAuthRequest(true);
  }
}

(async function () {
  const args = process.argv.slice(2);
  await main(args[0]);
})();
