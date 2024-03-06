/* eslint-disable @typescript-eslint/no-var-requires */
import { ZKProof } from '@iden3/js-jwz';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs/promises';
import { witnessBuilder } from './witness_calculator';
import { byteDecoder, CircuitId, IZKProver } from '@0xpolygonid/js-sdk';

/**
 *  NativeProver service responsible for zk generation and verification of groth16 algorithm with bn128 curve
 * @public
 * @class NativeProver
 * @implements implements IZKProver interface
 */
export class RapidSnarkProver implements IZKProver {
  constructor(private readonly _baseCircuitPath: string, private readonly _binariesPath: string) {}

  /**
   * verifies zero knowledge proof
   *
   * @param {ZKProof} zkp - zero knowledge proof that will be verified
   * @param {string} circuitId - circuit id for proof verification
   * @returns `Promise<ZKProof>`
   */
  async verify(zkp: ZKProof, circuitId: CircuitId): Promise<boolean> {
    try {
      const circuitPath = `${this._baseCircuitPath}/${circuitId}`;
      await Promise.all([
        fs.writeFile(`${circuitPath}/proof.json`, JSON.stringify(zkp.proof)),
        fs.writeFile(`${circuitPath}/public.json`, JSON.stringify(zkp.pub_signals))
      ]);
      const result = execFileSync(`${this._binariesPath}/verifier`, [
        `${circuitPath}/public.json`,
        `${circuitPath}/proof.json`
      ]);

      return result.toString().toUpperCase().includes('VALID PROOF');
    } catch (error) {
      console.error('Error while verifying proof', error);
      return false;
    }
  }

  /**
   * generates zero knowledge proof
   *
   * @param {Uint8Array} inputs - inputs that will be used for proof generation
   * @param {string} circuitId - circuit id for proof generation
   * @returns `Promise<ZKProof>`
   */
  async generate(inputs: Uint8Array, circuitId: CircuitId): Promise<ZKProof> {
    const circuitPath = `${this._baseCircuitPath}/${circuitId}`;

    const circuitWasm: Uint8Array = await fs.readFile(`${circuitPath}/circuit.wasm`);
    const witnessCalculator = await witnessBuilder(circuitWasm);
    const parsedData = JSON.parse(byteDecoder.decode(inputs));
    const wtnsBytes: Uint8Array = await witnessCalculator.calculateWTNSBin(parsedData, 0);
    await fs.writeFile(`${this._baseCircuitPath}/${circuitId}/witness.wtns`, wtnsBytes);
    console.time('rapidsnark generate');
    const [proofPath, publicPath] = [`${circuitPath}/proof.json`, `${circuitPath}/public.json`];
    try {
    const result = 
    execFileSync(`${this._binariesPath}/prover`, [
      `${circuitPath}/circuit_final.zkey`,
      `${circuitPath}/witness.wtns`,
      proofPath,
      publicPath
    ]);
    console.log(result.toString());
    } catch(e) {
        console.log(e);
    }

  

    const [proofs, pub_signals] = await Promise.all([
      fs.readFile(proofPath, 'utf-8'),
      fs.readFile(publicPath, 'utf-8')
    ]);

    console.timeEnd('rapidsnark generate');
    return {
      proof: JSON.parse(proofs),
      pub_signals: JSON.parse(pub_signals)
    };
  }
}