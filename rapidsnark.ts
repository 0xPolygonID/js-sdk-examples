/* eslint-disable @typescript-eslint/no-var-requires */
import { ZKProof } from '@iden3/js-jwz';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
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
      fs.writeFileSync(`${circuitPath}/proof.json`, JSON.stringify(zkp.proof));
      fs.writeFileSync(`${circuitPath}/public.json`, JSON.stringify(zkp.pub_signals));

      const result = execFileSync(`${this._binariesPath}/verifier`, [
        `${circuitPath}/public.json`,
        `${circuitPath}/proof.json`
      ]);

      fs.unlinkSync(`${circuitPath}/proof.json`);
      fs.unlinkSync(`${circuitPath}/public.json`);

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

    const circuitWasm: Uint8Array = fs.readFileSync(`${circuitPath}/circuit.wasm`);
    const witnessCalculator = await witnessBuilder(circuitWasm);
    const parsedData = JSON.parse(byteDecoder.decode(inputs));
    const wtnsBytes: Uint8Array = await witnessCalculator.calculateWTNSBin(parsedData, 0);
    fs.writeFileSync(`${this._baseCircuitPath}/${circuitId}/witness.wtns`, wtnsBytes);
    const [proofPath, publicPath] = [`${circuitPath}/proof.json`, `${circuitPath}/public.json`];
    try {
      const result = execFileSync(`${this._binariesPath}/prover`, [
        `${circuitPath}/circuit_final.zkey`,
        `${circuitPath}/witness.wtns`,
        proofPath,
        publicPath
      ]);
      console.log(result.toString());

      const [proofs, pub_signals] = [
        fs.readFileSync(proofPath, 'utf-8'),
        fs.readFileSync(publicPath, 'utf-8')
      ];

      fs.unlinkSync(proofPath);
      fs.unlinkSync(publicPath);
      fs.unlinkSync(`${circuitPath}/witness.wtns`);

      return {
        proof: JSON.parse(proofs),
        pub_signals: JSON.parse(pub_signals)
      };
    } catch (e) {
      console.error(e);

      throw new Error('Error while generating proof');
    }
  }
}
