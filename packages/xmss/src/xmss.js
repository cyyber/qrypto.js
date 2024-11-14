import { coreHash, prf } from './hash.js';
import { setChainAddr, setOTSAddr, setType, toByteLittleEndian } from './helper.js';
import { bdsRound, bdsTreeHashUpdate, expandSeed, genChain, getSeed } from './xmssFast.js';

/**
 * @param {Uint8Array} output
 * @param {Uint32Array[number]} outputLen
 * @param {Uint8Array} input
 * @param {WOTSParams} params
 */
export function calcBaseW(output, outputLen, input, params) {
  let inIndex = 0;
  let outIndex = 0;
  let [total] = new Uint32Array([0]);
  let [bits] = new Uint32Array([0]);

  for (let consumed = 0; consumed < outputLen; consumed++) {
    if (bits === 0) {
      [total] = new Uint32Array([input[inIndex]]);
      inIndex++;
      [bits] = new Uint32Array([bits + 8]);
    }
    [bits] = new Uint32Array([bits - params.logW]);
    output.set([new Uint8Array([(total >>> bits) & (params.w - 1)])[0]], outIndex);
    outIndex++;
  }
}

/**
 * @param {HashFunction} hashFunction
 * @param {Uint8Array} sig
 * @param {Uint8Array} msg
 * @param {Uint8Array} sk
 * @param {WOTSParams} params
 * @param {Uint8Array} pubSeed
 * @param {Uint8Array} addr
 */
export function wotsSign(hashFunction, sig, msg, sk, params, pubSeed, addr) {
  if (addr.length !== 8) {
    throw new Error('addr should be an array of size 8');
  }

  const baseW = new Uint8Array(params.len);
  let [csum] = new Uint32Array([0]);

  calcBaseW(baseW, params.len1, msg, params);

  for (let i = 0; i < params.len1; i++) {
    csum += params.w - 1 - new Uint32Array([baseW[i]])[0];
  }

  csum <<= 8 - ((params.len2 * params.logW) % 8);

  const len2Bytes = (params.len2 * params.logW + 7) / 8;

  const cSumBytes = new Uint8Array(len2Bytes);
  toByteLittleEndian(cSumBytes, csum, len2Bytes);

  const cSumBaseW = new Uint8Array(params.len2);

  calcBaseW(cSumBaseW, params.len2, cSumBytes, params);

  for (let i = 0; i < params.len2; i++) {
    baseW.set([cSumBaseW[i]], params.len1 + i);
  }

  expandSeed(hashFunction, sig, sk, params.n, params.len);

  for (let i = 0; i < params.len; i++) {
    setChainAddr(addr, i);
    const offset = i * params.n;
    genChain(
      hashFunction,
      sig.subarray(offset, offset + params.n),
      sig.subarray(offset, offset + params.n),
      0,
      new Uint32Array([baseW[i]])[0],
      params,
      pubSeed,
      addr
    );
  }
}

/**
 * @param {Uint32Array[number]} keySize
 * @returns {Uint32Array[number]}
 */
export function calculateSignatureBaseSize(keySize) {
  return 4 + 32 + keySize;
}

/**
 * @param {XMSSParams} params
 * @returns {Uint32Array[number]}
 */
export function getSignatureSize(params) {
  const signatureBaseSize = calculateSignatureBaseSize(params.wotsParams.keySize);
  return signatureBaseSize + params.h * 32;
}

/**
 * @param {HashFunction} hashFunction
 * @param {Uint8Array} out
 * @param {Uint8Array} input
 * @param {Uint8Array} key
 * @param {Uint32Array[number]} n
 * @returns {{ error: string }}
 */
export function hMsg(hashFunction, out, input, key, n) {
  if (key.length !== 3 * n) {
    return {
      error: `H_msg takes 3n-bit keys, we got n=${n} but a keylength of ${key.length}.`,
    };
  }
  coreHash(hashFunction, out, 2, key, key.length, input, input.length, n);
  return { error: null };
}

/**
 * @param {HashFunction} hashFunction
 * @param {XMSSParams} params
 * @param {Uint8Array} sk
 * @param {BDSState} bdsState
 * @param {Uint8Array} message
 * @returns {SignatureReturnType}
 */
export function xmssFastSignMessage(hashFunction, params, sk, bdsState, message) {
  const { n } = params;

  const [idx] = new Uint32Array([
    (new Uint32Array([sk[0]])[0] << 24) |
      (new Uint32Array([sk[1]])[0] << 16) |
      (new Uint32Array([sk[2]])[0] << 8) |
      new Uint32Array([sk[3]])[0],
  ]);

  const skSeed = new Uint8Array(n);
  for (let skSeedIndex = 0, skIndex = 4; skSeedIndex < skSeed.length && skIndex < 4 + n; skSeedIndex++, skIndex++) {
    skSeed.set([sk[skIndex]], skSeedIndex);
  }
  const skPRF = new Uint8Array(n);
  for (let skPrfIndex = 0, skIndex = 4 + n; skPrfIndex < skPRF.length && skIndex < 4 + n + n; skPrfIndex++, skIndex++) {
    skPRF.set([sk[skIndex]], skPrfIndex);
  }
  const pubSeed = new Uint8Array(n);
  for (
    let pubSeedIndex = 0, skIndex = 4 + 2 * n;
    pubSeedIndex < pubSeed.length && skIndex < 4 + 2 * n + n;
    pubSeedIndex++, skIndex++
  ) {
    pubSeed.set([sk[skIndex]], pubSeedIndex);
  }

  const idxBytes32 = new Uint8Array(32);
  toByteLittleEndian(idxBytes32, idx, 32);

  const hashKey = new Uint8Array(3 * n);

  sk.set([
    new Uint8Array([((idx + 1) >>> 24) & 0xff])[0],
    new Uint8Array([((idx + 1) >>> 16) & 0xff])[0],
    new Uint8Array([((idx + 1) >>> 8) & 0xff])[0],
    new Uint8Array([(idx + 1) & 0xff])[0],
  ]);

  const R = new Uint8Array(n);
  const otsAddr = new Uint32Array(8);

  prf(hashFunction, R, idxBytes32, skPRF, n);
  for (let hashKeyIndex = 0, rIndex = 0; hashKeyIndex < n && rIndex < R.length; hashKeyIndex++, rIndex++) {
    hashKey.set([R[rIndex]], hashKeyIndex);
  }
  for (
    let hashKeyIndex = n, skIndex = 4 + 3 * n;
    hashKeyIndex < n + n && skIndex < 4 + 3 * n + n;
    hashKeyIndex++, skIndex++
  ) {
    hashKey.set([sk[skIndex]], hashKeyIndex);
  }
  toByteLittleEndian(hashKey.subarray(2 * n, 2 * n + n), idx, n);
  const msgHash = new Uint8Array(n);
  const { error } = hMsg(hashFunction, msgHash, message, hashKey, n);
  if (error !== null) {
    return { sigMsg: null, error };
  }
  let [sigMsgLen] = new Uint32Array([0]);
  const sigMsg = new Uint8Array(getSignatureSize(params));
  sigMsg.set([
    new Uint8Array([(idx >>> 24) & 0xff])[0],
    new Uint8Array([(idx >>> 16) & 0xff])[0],
    new Uint8Array([(idx >>> 8) & 0xff])[0],
    new Uint8Array([idx & 0xff])[0],
  ]);

  sigMsgLen += 4;
  for (let i = 0; i < n; i++) {
    sigMsg.set([R[i]], sigMsgLen + i);
  }

  sigMsgLen += n;

  setType(otsAddr, 0);
  setOTSAddr(otsAddr, idx);

  const otsSeed = new Uint8Array(n);
  getSeed(hashFunction, otsSeed, skSeed, n, otsAddr);

  wotsSign(hashFunction, sigMsg.subarray(sigMsgLen), msgHash, otsSeed, params.wotsParams, pubSeed, otsAddr);

  sigMsgLen += params.wotsParams.keySize;

  for (
    let sigMsgIndex = sigMsgLen, authIndex = 0;
    sigMsgIndex < sigMsgLen + params.h * params.n && authIndex < params.h * params.n;
    sigMsgIndex++, authIndex++
  ) {
    sigMsg.set([bdsState.auth[authIndex]], sigMsgIndex);
  }

  if (idx < (new Uint32Array([1])[0] << params.h) - 1) {
    bdsRound(hashFunction, bdsState, idx, skSeed, params, pubSeed, otsAddr);
    bdsTreeHashUpdate(hashFunction, bdsState, (params.h - params.k) >>> 1, skSeed, params, pubSeed, otsAddr);
  }

  return { sigMsg, error: null };
}
