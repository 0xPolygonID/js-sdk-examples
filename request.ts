import { byteEncoder, createSchemaHash } from "@0xpolygonid/js-sdk";
import { Path, getDocumentLoader } from "@iden3/js-jsonld-merklization";

const pathToCredentialSubject =
    "https://www.w3.org/2018/credentials#credentialSubject";


export async function generateRequestData() {

    const url = `https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld`;
    const type = "KYCAgeCredential";
    const fieldName = "birthday"; // in form of field.field2.field3 field must be present in the credential subject

    const opts = { ipfsGatewayURL: 'https://ipfs.io' } // can be your IFPS gateway if your work with ipfs schemas or empty object
    const ldCtx = (await getDocumentLoader(opts)(url)).document
    const ldJSONStr = JSON.stringify(ldCtx);
    // const ldBytes = byteEncoder.encode(ldJSONStr);
    const typeId = await Path.getTypeIDFromContext(ldJSONStr, type);
    const schemaHash = createSchemaHash(byteEncoder.encode(typeId))
    console.log("schemaId", schemaHash.bigInt().toString());

    // you can use custom IPFS
    const path = await Path.getContextPathKey(ldJSONStr, type, fieldName, opts);
    path.prepend([pathToCredentialSubject])
    const pathBigInt = await path.mtEntry()

    console.log("path", pathBigInt.toString());


}
