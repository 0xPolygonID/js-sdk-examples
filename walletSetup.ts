const getCurveFromName = require("ffjavascript").getCurveFromName;
import { proving } from "@iden3/js-jwz";
import {
  BjjProvider,
  CredentialStorage,
  CredentialWallet,
  defaultEthConnectionConfig,
  EthStateStorage,
  ICredentialWallet,
  IDataStorage,
  Identity,
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
  EthConnectionConfig,
  CircuitStorage,
  CircuitData,
  FSKeyLoader,
  CircuitId,
  IStateStorage,
  ProofService,
  ICircuitStorage,
  CredentialStatusType,
  CredentialStatusResolverRegistry,
  IssuerResolver,
  RHSResolver,
  OnChainResolver,
  AuthDataPrepareFunc,
  StateVerificationFunc,
  DataPrepareHandlerFunc,
  VerificationHandlerFunc,
  IPackageManager,
  VerificationParams,
  ProvingParams,
  ZKPPacker,
  PlainPacker,
  PackageManager,
  AgentResolver,
} from "@0xpolygonid/js-sdk";
import path from "path";
import dotenv from "dotenv";
dotenv.config();

const rpcUrl = process.env.RPC_URL as string;
const contractAddress = process.env.CONTRACT_ADDRESS as string;
const circuitsFolder = process.env.CIRCUITS_PATH as string;

export function initDataStorage(): IDataStorage {
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

export async function initIdentityWallet(
  dataStorage: IDataStorage,
  credentialWallet: ICredentialWallet
): Promise<IIdentityWallet> {
  const memoryKeyStore = new InMemoryPrivateKeyStore();
  const bjjProvider = new BjjProvider(KmsKeyType.BabyJubJub, memoryKeyStore);
  const kms = new KMS();
  kms.registerKeyProvider(KmsKeyType.BabyJubJub, bjjProvider);

  return new IdentityWallet(kms, dataStorage, credentialWallet);
}

export async function initMemoryIdentityWallet() {
  const dataStorage = initDataStorage();
  const credentialWallet = await initCredentialWallet(dataStorage);
  const identityWallet = await initIdentityWallet(
    dataStorage,
    credentialWallet
  );

  return {
    dataStorage,
    credentialWallet,
    identityWallet,
  };
}

export async function initCredentialWallet(
  dataStorage: IDataStorage
): Promise<CredentialWallet> {
  const resolvers = new CredentialStatusResolverRegistry();
  resolvers.register(
    CredentialStatusType.SparseMerkleTreeProof,
    new IssuerResolver()
  );
  resolvers.register(
    CredentialStatusType.Iden3ReverseSparseMerkleTreeProof,
    new RHSResolver(dataStorage.states)
  );
  resolvers.register(
    CredentialStatusType.Iden3OnchainSparseMerkleTreeProof2023,
    new OnChainResolver([defaultEthConnectionConfig])
  );
  resolvers.register(
    CredentialStatusType.Iden3commRevocationStatusV1,
    new AgentResolver()
  );

  return new CredentialWallet(dataStorage, resolvers);
}

export async function initCircuitStorage(): Promise<ICircuitStorage> {
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
export async function initProofService(
  identityWallet: IIdentityWallet,
  credentialWallet: ICredentialWallet,
  stateStorage: IStateStorage,
  circuitStorage: ICircuitStorage
): Promise<ProofService> {
  return new ProofService(
    identityWallet,
    credentialWallet,
    circuitStorage,
    stateStorage,
    { ipfsGatewayURL: "https://ipfs.io" }
  );
}

export async function initPackageManager(
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
