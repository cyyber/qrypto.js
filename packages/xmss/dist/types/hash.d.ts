/**
 * @param {HashFunction} hashFunction
 * @param {Uint8Array} out
 * @param {Uint32Array[number]} typeValue
 * @param {Uint8Array} key
 * @param {Uint32Array[number]} keyLen
 * @param {Uint8Array} input
 * @param {Uint32Array[number]} inLen
 * @param {Uint32Array[number]} n
 */
export function coreHash(hashFunction: HashFunction, out: Uint8Array, typeValue: Uint32Array[number], key: Uint8Array, keyLen: Uint32Array[number], input: Uint8Array, inLen: Uint32Array[number], n: Uint32Array[number]): void;
/**
 * @param {HashFunction} hashFunction
 * @param {Uint8Array} out
 * @param {Uint8Array} input
 * @param {Uint8Array} key
 * @param {Uint32Array[number]} keyLen
 */
export function prf(hashFunction: HashFunction, out: Uint8Array, input: Uint8Array, key: Uint8Array, keyLen: Uint32Array[number]): void;
/**
 * @param {HashFunction} hashFunction
 * @param {Uint8Array} out
 * @param {Uint8Array} input
 * @param {Uint8Array} pubSeed
 * @param {Uint32Array} addr
 * @param {Uint32Array[number]} n
 */
export function hashH(hashFunction: HashFunction, out: Uint8Array, input: Uint8Array, pubSeed: Uint8Array, addr: Uint32Array, n: Uint32Array[number]): void;
//# sourceMappingURL=hash.d.ts.map