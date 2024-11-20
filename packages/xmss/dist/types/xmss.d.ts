/**
 * @param {Uint8Array} output
 * @param {Uint32Array[number]} outputLen
 * @param {Uint8Array} input
 * @param {WOTSParams} params
 */
export function calcBaseW(output: Uint8Array, outputLen: Uint32Array[number], input: Uint8Array, params: WOTSParams): void;
/**
 * @param {HashFunction} hashFunction
 * @param {Uint8Array} sig
 * @param {Uint8Array} msg
 * @param {Uint8Array} sk
 * @param {WOTSParams} params
 * @param {Uint8Array} pubSeed
 * @param {Uint8Array} addr
 */
export function wotsSign(hashFunction: HashFunction, sig: Uint8Array, msg: Uint8Array, sk: Uint8Array, params: WOTSParams, pubSeed: Uint8Array, addr: Uint8Array): void;
/**
 * @param {Uint32Array[number]} keySize
 * @returns {Uint32Array[number]}
 */
export function calculateSignatureBaseSize(keySize: Uint32Array[number]): Uint32Array[number];
/**
 * @param {XMSSParams} params
 * @returns {Uint32Array[number]}
 */
export function getSignatureSize(params: XMSSParams): Uint32Array[number];
/**
 * @param {HashFunction} hashFunction
 * @param {Uint8Array} out
 * @param {Uint8Array} input
 * @param {Uint8Array} key
 * @param {Uint32Array[number]} n
 * @returns {{ error: string }}
 */
export function hMsg(hashFunction: HashFunction, out: Uint8Array, input: Uint8Array, key: Uint8Array, n: Uint32Array[number]): {
    error: string;
};
/**
 * @param {HashFunction} hashFunction
 * @param {XMSSParams} params
 * @param {Uint8Array} sk
 * @param {BDSState} bdsState
 * @param {Uint8Array} message
 * @returns {SignatureReturnType}
 */
export function xmssFastSignMessage(hashFunction: HashFunction, params: XMSSParams, sk: Uint8Array, bdsState: BDSState, message: Uint8Array): SignatureReturnType;
/**
 * @param {Uint32Array[number]} sigSize
 * @param {Uint32Array[number]} wotsParamW
 * @returns {Uint32Array[number]}
 */
export function getHeightFromSigSize(sigSize: Uint32Array[number], wotsParamW: Uint32Array[number]): Uint32Array[number];
/**
 * @param {HashFunction} hashfunction
 * @param {Uint8Array} pk
 * @param {Uint8Array} sig
 * @param {Uint8Array} msg
 * @param {WOTSParams} wotsParams
 * @param {Uint8Array} pubSeed
 * @param {Uint32Array} addr
 */
export function wotsPKFromSig(hashfunction: HashFunction, pk: Uint8Array, sig: Uint8Array, msg: Uint8Array, wotsParams: WOTSParams, pubSeed: Uint8Array, addr: Uint32Array): void;
/**
 * @param {HashFunction} hashFunction
 * @param {Uint8Array} root
 * @param {Uint8Array} leaf
 * @param {Uint32Array[number]} leafIdx
 * @param {Uint8Array} authpath
 * @param {Uint32Array[number]} n
 * @param {Uint32Array[number]} h
 * @param {Uint8Array} pubSeed
 * @param {Uint32Array} addr
 */
export function validateAuthPath(hashFunction: HashFunction, root: Uint8Array, leaf: Uint8Array, leafIdx: Uint32Array[number], authpath: Uint8Array, n: Uint32Array[number], h: Uint32Array[number], pubSeed: Uint8Array, addr: Uint32Array): void;
/**
 * @param {HashFunction} hashFunction
 * @param {WOTSParams} wotsParams
 * @param {Uint8Array} msg
 * @param {Uint8Array} sigMsg
 * @param {Uint8Array} pk
 * @param {Uint32Array[number]} h
 * @returns {boolean}
 */
export function xmssVerifySig(hashFunction: HashFunction, wotsParams: WOTSParams, msg: Uint8Array, sigMsg: Uint8Array, pk: Uint8Array, h: Uint32Array[number]): boolean;
//# sourceMappingURL=xmss.d.ts.map