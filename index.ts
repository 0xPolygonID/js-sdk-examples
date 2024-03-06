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
  IdentityCreationOptions,
  ProofType,
  AuthorizationRequestMessageBody,
  byteEncoder
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
  const { did, credential } = await identityWallet.createIdentity({
    ...defaultIdentityCreationOptions
  });

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

  const { did: userDID, credential: authBJJCredentialUser } = await identityWallet.createIdentity({
    ...defaultIdentityCreationOptions
  });

  console.log('=============== user did ===============');
  console.log(userDID.string());

  const { did: issuerDID, credential: issuerAuthBJJCredential } =
    await identityWallet.createIdentity({ ...defaultIdentityCreationOptions });

  console.log('=============== issuer did ===============');
  console.log(issuerDID.string());
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

  const { did: userDID, credential: authBJJCredentialUser } = await identityWallet.createIdentity({
    ...defaultIdentityCreationOptions
  });

  console.log('=============== user did ===============');
  console.log(userDID.string());

  const { did: issuerDID, credential: issuerAuthBJJCredential } =
    await identityWallet.createIdentity({ ...defaultIdentityCreationOptions });

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

async function transitStateThirdPartyDID() {
  console.log('=============== THIRD PARTY DID: transit state  ===============');
  core.registerDidMethodNetwork({
    method: 'thirdparty',
    methodByte: 0b1000_0001,
    blockchain: 'linea',
    network: 'test',
    networkFlag: 0b01000000 | 0b00000001,
    chainId: 11155111
  });

  core.registerDidMethodNetwork({
    method: 'iden3',
    blockchain: 'linea',
    network: 'test',
    networkFlag: 0b11000000 | 0b00000011
  });

  const { dataStorage, credentialWallet, identityWallet } = await initInMemoryDataStorageAndWallets(
    {
      rpcUrl: process.env.THIRD_PARTY_RPC_URL as string,
      contractAddress: process.env.THIRD_PARTY_CONTRACT_ADDRESS as string
    }
  );

  const circuitStorage = await initCircuitStorage();
  const proofService = await initProofService(
    identityWallet,
    credentialWallet,
    dataStorage.states,
    circuitStorage
  );

  const method = core.DidMethod.thirdparty;
  const blockchain = core.Blockchain.linea;
  const networkId = core.NetworkId.test;
  const { did: userDID } = await identityWallet.createIdentity({
    method,
    blockchain,
    networkId,
    revocationOpts: {
      type: CredentialStatusType.Iden3ReverseSparseMerkleTreeProof,
      id: rhsUrl
    }
  });

  console.log('=============== third party: user did ===============');
  console.log(userDID.string());

  const { did: issuerDID } = await identityWallet.createIdentity({
    method: core.DidMethod.Iden3,
    blockchain: core.Blockchain.linea,
    networkId: core.NetworkId.test,
    revocationOpts: {
      type: CredentialStatusType.Iden3ReverseSparseMerkleTreeProof,
      id: rhsUrl
    }
  });
  console.log('=============== third party: issuer did ===============');
  console.log(issuerDID.string());

  const credentialRequest = createKYCAgeCredential(userDID);
  const credential = await identityWallet.issueCredential(issuerDID, credentialRequest);

  await dataStorage.credential.saveCredential(credential);

  console.log(
    '================= third party: generate Iden3SparseMerkleTreeProof ======================='
  );

  const res = await identityWallet.addCredentialsToMerkleTree([credential], issuerDID);

  console.log('================= third party: push states to rhs ===================');

  await identityWallet.publishStateToRHS(issuerDID, rhsUrl);

  console.log('================= publish to blockchain ===================');

  const ethSigner = new ethers.Wallet(
    process.env.THIRD_PARTY_WALLET_KEY as string,
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

  const { did: userDID, credential: authBJJCredentialUser } = await identityWallet.createIdentity({
    ...defaultIdentityCreationOptions
  });

  console.log('=============== user did ===============');
  console.log(userDID.string());

  const { did: issuerDID, credential: issuerAuthBJJCredential } =
    await identityWallet.createIdentity({ ...defaultIdentityCreationOptions });

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

  const { did: userDID, credential: authBJJCredentialUser } = await identityWallet.createIdentity({
    ...defaultIdentityCreationOptions
  });

  console.log('=============== user did ===============');
  console.log(userDID.string());

  const { did: issuerDID, credential: issuerAuthBJJCredential } =
    await identityWallet.createIdentity({ ...defaultIdentityCreationOptions });

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

  const { did: userDID, credential: authBJJCredentialUser } = await identityWallet.createIdentity({
    ...defaultIdentityCreationOptions
  });

  console.log('=============== user did ===============');
  console.log(userDID.string());

  const { did: issuerDID, credential: issuerAuthBJJCredential } =
    await identityWallet.createIdentity({ ...defaultIdentityCreationOptions });

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

async function handleAuthRequestWithProfilesV3CircuitBeta() {
  console.log('=============== handle auth request with profiles v3 circuits beta ===============');

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

  const { did: userDID, credential: authBJJCredentialUser } = await identityWallet.createIdentity({
    ...defaultIdentityCreationOptions
  });

  console.log('=============== user did ===============');
  console.log(userDID.string());

  const { did: issuerDID, credential: issuerAuthBJJCredential } =
    await identityWallet.createIdentity({ ...defaultIdentityCreationOptions });

  // credential is issued on the profile!
  const profileDID = await identityWallet.createProfile(userDID, 50, issuerDID.string());

  const credentialRequest = createKYCAgeCredential(profileDID);
  const credential = await identityWallet.issueCredential(issuerDID, credentialRequest);

  await dataStorage.credential.saveCredential(credential);

  console.log('================= generate credentialAtomicV3 ===================');

  const proofReq: ZeroKnowledgeProofRequest = {
    id: 19,
    circuitId: CircuitId.AtomicQueryV3,
    params: {
      nullifierSessionId: '123443290439234342342423423423423'
    },
    query: {
      groupId: 1,
      allowedIssuers: ['*'],
      proofType: ProofType.BJJSignature,
      type: credentialRequest.type,
      context:
        'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld',
      credentialSubject: {
        documentType: {}
      }
    }
  };

  const linkedProof: ZeroKnowledgeProofRequest = {
    id: 20,
    circuitId: CircuitId.LinkedMultiQuery10,
    optional: false,
    query: {
      groupId: 1,
      proofType: ProofType.BJJSignature,
      allowedIssuers: ['*'],
      type: credentialRequest.type,
      context:
        'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld',
      credentialSubject: {
        birthday: {
          $lt: 20010101
        }
      }
    }
  };

  console.log('=================  credential auth request ===================');
  const verifierDID = 'did:polygonid:polygon:mumbai:2qLWqgjWa1cGnmPwCreXuPQrfLrRrzDL1evD6AG7p7';

  const authRequest: AuthorizationRequestMessage = {
    id: 'fe6354fe-3db2-48c2-a779-e39c2dda8d90',
    thid: 'fe6354fe-3db2-48c2-a779-e39c2dda8d90',
    typ: PROTOCOL_CONSTANTS.MediaType.PlainMessage,
    from: verifierDID,
    type: PROTOCOL_CONSTANTS.PROTOCOL_MESSAGE_TYPE.AUTHORIZATION_REQUEST_MESSAGE_TYPE,
    body: {
      callbackUrl: 'http://testcallback.com',
      message: 'v3 beta',
      scope: [proofReq, linkedProof],
      reason: 'selective disclosure of document type,'
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

  const { did: userDID, credential: authBJJCredentialUser } = await identityWallet.createIdentity({
    ...defaultIdentityCreationOptions
  });

  console.log('=============== user did ===============');
  console.log(userDID.string());

  const { did: issuerDID, credential: issuerAuthBJJCredential } =
    await identityWallet.createIdentity({ ...defaultIdentityCreationOptions });

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

async function handleAuthRequestV3CircuitsBetaStateTransition() {
  console.log('=============== handle auth request no issuer state transition V3 ===============');

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

  const authV2Data = await circuitStorage.loadCircuitData(CircuitId.AuthV2);
  const pm = await initPackageManager(
    authV2Data,
    proofService.generateAuthV2Inputs.bind(proofService),
    proofService.verifyState.bind(proofService)
  );

  const authHandler = new AuthHandler(pm, proofService);

  const { did: issuerDID, credential: issuerAuthBJJCredential } =
    await identityWallet.createIdentity({ ...defaultIdentityCreationOptions });

  console.log('=============== user did ===============', issuerDID.string());

  const { did: userDID, credential: authBJJCredentialUser } = await identityWallet.createIdentity({
    ...defaultIdentityCreationOptions
  });

  console.log('=============== user did ===============', userDID.string());

  const profileDID = await identityWallet.createProfile(userDID, 777, issuerDID.string());

  const claimReq: CredentialRequest = {
    credentialSchema:
      'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json/kyc-nonmerklized.json',
    type: 'KYCAgeCredential',
    credentialSubject: {
      id: userDID.string(),
      birthday: 19960424,
      documentType: 99
    },
    expiration: 2793526400,
    revocationOpts: {
      type: CredentialStatusType.Iden3ReverseSparseMerkleTreeProof,
      id: rhsUrl
    }
  };
  const issuedCred = await identityWallet.issueCredential(issuerDID, claimReq);
  await credentialWallet.save(issuedCred);
  console.log('=============== issued birthday credential ===============');

  const res = await identityWallet.addCredentialsToMerkleTree([issuedCred], issuerDID);
  console.log('=============== added to merkle tree ===============');

  await identityWallet.publishStateToRHS(issuerDID, rhsUrl);
  console.log('=============== published to rhs ===============');

  const ethSigner = new ethers.Wallet(walletKey, (dataStorage.states as EthStateStorage).provider);

  const txId = await proofService.transitState(
    issuerDID,
    res.oldTreeState,
    true,
    dataStorage.states,
    ethSigner
  );

  console.log('=============== state transition ===============', txId);

  const credsWithIden3MTPProof = await identityWallet.generateIden3SparseMerkleTreeProof(
    issuerDID,
    res.credentials,
    txId
  );

  await credentialWallet.saveAll(credsWithIden3MTPProof);

  console.log('=============== saved credentials with mtp proof ===============');

  const employeeCredRequest: CredentialRequest = {
    credentialSchema:
      'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json/KYCEmployee-v101.json',
    type: 'KYCEmployee',
    credentialSubject: {
      id: profileDID.string(),
      ZKPexperiance: true,
      hireDate: '2023-12-11',
      position: 'boss',
      salary: 200,
      documentType: 1
    },
    revocationOpts: {
      type: CredentialStatusType.Iden3ReverseSparseMerkleTreeProof,
      id: rhsUrl
    }
  };
  const employeeCred = await identityWallet.issueCredential(issuerDID, employeeCredRequest);

  await credentialWallet.save(employeeCred);

  console.log('=============== issued employee credential ===============');

  console.log(
    '=============== generate ZeroKnowledgeProofRequest MTP + SIG + with Linked proof ==================='
  );

  const proofReqs: ZeroKnowledgeProofRequest[] = [
    {
      id: 1,
      circuitId: CircuitId.AtomicQueryV3,
      optional: false,
      query: {
        allowedIssuers: ['*'],
        type: claimReq.type,
        proofType: ProofType.Iden3SparseMerkleTreeProof,
        context:
          'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-nonmerklized.jsonld',
        credentialSubject: {
          documentType: {
            $eq: 99
          }
        }
      }
    },
    {
      id: 2,
      circuitId: CircuitId.AtomicQueryV3,
      optional: false,
      params: {
        nullifierSessionId: 12345
      },
      query: {
        groupId: 1,
        proofType: ProofType.BJJSignature,
        allowedIssuers: ['*'],
        type: 'KYCEmployee',
        context:
          'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v101.json-ld',
        skipClaimRevocationCheck: true,
        credentialSubject: {
          salary: {
            $eq: 200
          }
        }
      }
    },
    {
      id: 3,
      circuitId: CircuitId.LinkedMultiQuery10,
      optional: false,
      query: {
        groupId: 1,
        proofType: ProofType.Iden3SparseMerkleTreeProof,
        allowedIssuers: ['*'],
        type: 'KYCEmployee',
        skipClaimRevocationCheck: true,
        context:
          'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v101.json-ld',
        credentialSubject: {
          salary: {
            $ne: 300
          }
        }
      }
    }
  ];

  const authReqBody: AuthorizationRequestMessageBody = {
    callbackUrl: 'http://localhost:8080/callback?id=1234442-123123-123123',
    reason: 'reason',
    message: 'mesage',
    did_doc: {},
    scope: proofReqs
  };

  const id = globalThis.crypto.randomUUID();
  const authReq: AuthorizationRequestMessage = {
    id,
    typ: PROTOCOL_CONSTANTS.MediaType.PlainMessage,
    type: PROTOCOL_CONSTANTS.PROTOCOL_MESSAGE_TYPE.AUTHORIZATION_REQUEST_MESSAGE_TYPE,
    thid: id,
    body: authReqBody,
    from: issuerDID.string()
  };

  const msgBytes = byteEncoder.encode(JSON.stringify(authReq));
  console.log('=============== auth request ===============');

  const authHandlerRequest = await authHandler.handleAuthorizationRequest(userDID, msgBytes);
  console.log(JSON.stringify(authHandlerRequest, null, 2));
}

async function benchmarkHandleAuthRequest() {
  console.log('=============== handle benchmark AuthRequest ===============');

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

  const { did: userDID } = await identityWallet.createIdentity({
    ...defaultIdentityCreationOptions
  });

  const { did: issuerDID } =
    await identityWallet.createIdentity({ ...defaultIdentityCreationOptions });

  const credentialRequest = createKYCAgeCredential(userDID);
  const credential = await identityWallet.issueCredential(issuerDID, credentialRequest);

  await dataStorage.credential.saveCredential(credential);

  const proofReq0: ZeroKnowledgeProofRequest = {
    id: 19,
    circuitId: CircuitId.AtomicQuerySigV2,
    query: {
      allowedIssuers: ['*'],
      proofType: ProofType.BJJSignature,
      type: credentialRequest.type,
      context:
        'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld',
      credentialSubject: {
        documentType: {
          $lt: 200
        }
      }
    }
  };

  let proofReq1 = JSON.parse(JSON.stringify(proofReq0));
  let proofReq2 = JSON.parse(JSON.stringify(proofReq0));
  let proofReq3 = JSON.parse(JSON.stringify(proofReq0));
  let proofReq4 = JSON.parse(JSON.stringify(proofReq0));
  let proofReq5 = JSON.parse(JSON.stringify(proofReq0));
  let proofReq6 = JSON.parse(JSON.stringify(proofReq0));
  let proofReq7 = JSON.parse(JSON.stringify(proofReq0));
  let proofReq8 = JSON.parse(JSON.stringify(proofReq0));
  let proofReq9 = JSON.parse(JSON.stringify(proofReq0));

  proofReq1.id = 20;
  proofReq2.id = 21;
  proofReq3.id = 22;
  proofReq4.id = 23;
  proofReq5.id = 24;
  proofReq6.id = 25;
  proofReq7.id = 26;
  proofReq8.id = 27;
  proofReq9.id = 28;

  proofReq1.query.credentialSubject.documentType['$lt'] = 100;
  proofReq2.query.credentialSubject.documentType['$lt'] = 101;
  proofReq3.query.credentialSubject.documentType['$lt'] = 102;
  proofReq4.query.credentialSubject.documentType['$lt'] = 103;
  proofReq5.query.credentialSubject.documentType['$lt'] = 104;
  proofReq6.query.credentialSubject.documentType['$lt'] = 105;
  proofReq7.query.credentialSubject.documentType['$lt'] = 106;
  proofReq8.query.credentialSubject.documentType['$lt'] = 107;
  proofReq9.query.credentialSubject.documentType['$lt'] = 108;

  const verifierDID = 'did:polygonid:polygon:mumbai:2qLWqgjWa1cGnmPwCreXuPQrfLrRrzDL1evD6AG7p7';

  const authRequest1: AuthorizationRequestMessage = {
    id: 'fe6354fe-3db2-48c2-a779-e39c2dda8d90',
    thid: 'fe6354fe-3db2-48c2-a779-e39c2dda8d90',
    typ: PROTOCOL_CONSTANTS.MediaType.PlainMessage,
    from: verifierDID,
    type: PROTOCOL_CONSTANTS.PROTOCOL_MESSAGE_TYPE.AUTHORIZATION_REQUEST_MESSAGE_TYPE,
    body: {
      callbackUrl: 'http://testcallback.com',
      message: 'v3 beta',
      scope: [proofReq0],
      reason: '$lte for documentType'
    }
  };

  const authRequest3: AuthorizationRequestMessage = {
    id: 'fe6354fe-3db2-48c2-a779-e39c2dda8d90',
    thid: 'fe6354fe-3db2-48c2-a779-e39c2dda8d90',
    typ: PROTOCOL_CONSTANTS.MediaType.PlainMessage,
    from: verifierDID,
    type: PROTOCOL_CONSTANTS.PROTOCOL_MESSAGE_TYPE.AUTHORIZATION_REQUEST_MESSAGE_TYPE,
    body: {
      callbackUrl: 'http://testcallback.com',
      message: 'v3 beta',
      scope: [proofReq0, proofReq1, proofReq2],
      reason: '$lte for documentType'
    }
  };

  const authRequest10: AuthorizationRequestMessage = {
    id: 'fe6354fe-3db2-48c2-a779-e39c2dda8d90',
    thid: 'fe6354fe-3db2-48c2-a779-e39c2dda8d90',
    typ: PROTOCOL_CONSTANTS.MediaType.PlainMessage,
    from: verifierDID,
    type: PROTOCOL_CONSTANTS.PROTOCOL_MESSAGE_TYPE.AUTHORIZATION_REQUEST_MESSAGE_TYPE,
    body: {
      callbackUrl: 'http://testcallback.com',
      message: 'v3 beta',
      scope: [proofReq0, proofReq1, proofReq2, proofReq3, proofReq4, proofReq5, proofReq6, proofReq7, proofReq8, proofReq9],
      reason: '$lte for documentType'
    }
  };

  const authRawRequest1 = new TextEncoder().encode(JSON.stringify(authRequest1));
  const authRawRequest3 = new TextEncoder().encode(JSON.stringify(authRequest3));
  const authRawRequest10 = new TextEncoder().encode(JSON.stringify(authRequest10));

  const authV2Data = await circuitStorage.loadCircuitData(CircuitId.AuthV2);
  const pm = await initPackageManager(
    authV2Data,
    proofService.generateAuthV2Inputs.bind(proofService),
    proofService.verifyState.bind(proofService)
  );

  const authHandler = new AuthHandler(pm, proofService);

  let t0 = performance.now();
  const resp1 = await authHandler.handleAuthorizationRequest(userDID, authRawRequest1);
  let t1 = performance.now();
  console.log(`Call handleAuthorizationRequest with 1 request took ${t1 - t0} milliseconds.`);

  t0 = performance.now();
  const resp3 = await authHandler.handleAuthorizationRequest(userDID, authRawRequest3);
  t1 = performance.now();
  console.log(`Call handleAuthorizationRequest with 3 requests took ${t1 - t0} milliseconds.`);

  t0 = performance.now();
  const resp10 = await authHandler.handleAuthorizationRequest(userDID, authRawRequest10);
  t1 = performance.now();
  console.log(`Call handleAuthorizationRequest with 10 requests took ${t1 - t0} milliseconds.`);
}

async function benchmarkGenerateProof() {
  console.log('=============== handle benchmark generate proof ===============');

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

  const { did: userDID, credential: authBJJCredentialUser } = await identityWallet.createIdentity({
    ...defaultIdentityCreationOptions
  });

  const { did: issuerDID, credential: issuerAuthBJJCredential } =
    await identityWallet.createIdentity({ ...defaultIdentityCreationOptions });

  const credentialRequest = createKYCAgeCredential(userDID);
  const credential = await identityWallet.issueCredential(issuerDID, credentialRequest);

  await dataStorage.credential.saveCredential(credential);

  const proofReq0: ZeroKnowledgeProofRequest = {
    id: 19,
    circuitId: CircuitId.AtomicQuerySigV2,
    query: {
      allowedIssuers: ['*'],
      proofType: ProofType.BJJSignature,
      type: credentialRequest.type,
      context:
        'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld',
      credentialSubject: {
        documentType: {
          $lt: 200
        }
      }
    }
  };

  let proofReq1 = JSON.parse(JSON.stringify(proofReq0));
  let proofReq2 = JSON.parse(JSON.stringify(proofReq0));
  let proofReq3 = JSON.parse(JSON.stringify(proofReq0));
  let proofReq4 = JSON.parse(JSON.stringify(proofReq0));
  let proofReq5 = JSON.parse(JSON.stringify(proofReq0));
  let proofReq6 = JSON.parse(JSON.stringify(proofReq0));
  let proofReq7 = JSON.parse(JSON.stringify(proofReq0));
  let proofReq8 = JSON.parse(JSON.stringify(proofReq0));
  let proofReq9 = JSON.parse(JSON.stringify(proofReq0));

  proofReq1.id = 20;
  proofReq2.id = 21;
  proofReq3.id = 22;
  proofReq4.id = 23;
  proofReq5.id = 24;
  proofReq6.id = 25;
  proofReq7.id = 26;
  proofReq8.id = 27;
  proofReq9.id = 28;

  proofReq1.query.credentialSubject.documentType['$lt'] = 100;
  proofReq2.query.credentialSubject.documentType['$lt'] = 101;
  proofReq3.query.credentialSubject.documentType['$lt'] = 102;
  proofReq4.query.credentialSubject.documentType['$lt'] = 103;
  proofReq5.query.credentialSubject.documentType['$lt'] = 104;
  proofReq6.query.credentialSubject.documentType['$lt'] = 105;
  proofReq7.query.credentialSubject.documentType['$lt'] = 106;
  proofReq8.query.credentialSubject.documentType['$lt'] = 107;
  proofReq9.query.credentialSubject.documentType['$lt'] = 108;


  let t0 = performance.now();
  await proofService.generateProof(proofReq0, userDID);
  let t1 = performance.now();
  console.log(`Call generateProof with 1 request took ${t1 - t0} milliseconds.`);

  t0 = performance.now();
  const proof20 = proofService.generateProof(proofReq0, userDID);
  const proof21 = proofService.generateProof(proofReq1, userDID);
  const proof22 = proofService.generateProof(proofReq2, userDID);
  await Promise.all([proof20, proof21, proof22]);
  t1 = performance.now();
  console.log(`Call generateProof with 3 requests took ${t1 - t0} milliseconds.`);

  t0 = performance.now();
  const proof0 = proofService.generateProof(proofReq0, userDID);
  const proof1 = proofService.generateProof(proofReq1, userDID);
  const proof2 = proofService.generateProof(proofReq2, userDID);
  const proof3 = proofService.generateProof(proofReq3, userDID);
  const proof4 = proofService.generateProof(proofReq4, userDID);
  const proof5 = proofService.generateProof(proofReq5, userDID);
  const proof6 = proofService.generateProof(proofReq6, userDID);
  const proof7 = proofService.generateProof(proofReq7, userDID);
  const proof8 = proofService.generateProof(proofReq8, userDID);
  const proof9 = proofService.generateProof(proofReq9, userDID);
  await Promise.all([proof0, proof1, proof2, proof3, proof4, proof5, proof6, proof7, proof8, proof9]);
  t1 = performance.now();
  console.log(`Call generateProof with 10 requests took ${t1 - t0} milliseconds.`);
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
    case 'handleAuthRequestWithProfilesV3CircuitBeta':
      await handleAuthRequestWithProfilesV3CircuitBeta();
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
      await transitStateThirdPartyDID();
      break;

    case 'handleAuthRequestV3CircuitsBetaStateTransition':
      await handleAuthRequestV3CircuitsBetaStateTransition();
      break;
    case 'benchmarkHandleAuthRequest':
      await benchmarkHandleAuthRequest();
      break;
    case 'benchmarkHandleGenerateProof':
      await benchmarkGenerateProof();
      break;

    default:
      // default run all
      await identityCreation();
      await issueCredential();
      await transitState();
      await transitStateThirdPartyDID();
      await generateProofs();
      await handleAuthRequest();
      await handleAuthRequestWithProfiles();
      await handleAuthRequestWithProfilesV3CircuitBeta();
      await handleAuthRequestNoIssuerStateTransition();
      await generateRequestData();
      await generateProofs(true);
      await handleAuthRequest(true);
      await handleAuthRequestV3CircuitsBetaStateTransition();
      await benchmarkHandleAuthRequest();
      await benchmarkGenerateProof();
  }
}

(async function () {
  const args = process.argv.slice(2);
  await main(args[0]);
})();
