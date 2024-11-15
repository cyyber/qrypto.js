/**
 * @param {Uint8Array} out
 * @param {Uint8Array} msg
 * @returns {Uint8Array}
 */
export function shake128(out: Uint8Array, msg: Uint8Array): Uint8Array;
/**
 * @param {Uint8Array} out
 * @param {Uint8Array} msg
 * @returns {Uint8Array}
 */
export function shake256(out: Uint8Array, msg: Uint8Array): Uint8Array;
/**
 * @param {Uint8Array} out
 * @param {Uint8Array} msg
 * @returns {Uint8Array}
 */
export function sha256(out: Uint8Array, msg: Uint8Array): Uint8Array;
/**
 * @param {Uint32Array} addr
 * @param {Uint32Array[number]} typeValue
 */
export function setType(addr: Uint32Array, typeValue: Uint32Array[number]): void;
/**
 * @param {Uint32Array} addr
 * @param {Uint32Array[number]} lTree
 */
export function setLTreeAddr(addr: Uint32Array, lTree: Uint32Array[number]): void;
/**
 * @param {Uint32Array} addr
 * @param {Uint32Array[number]} ots
 */
export function setOTSAddr(addr: Uint32Array, ots: Uint32Array[number]): void;
/**
 * @param {Uint32Array} addr
 * @param {Uint32Array[number]} chain
 */
export function setChainAddr(addr: Uint32Array, chain: Uint32Array[number]): void;
/**
 * @param {Uint32Array} addr
 * @param {Uint32Array[number]} hash
 */
export function setHashAddr(addr: Uint32Array, hash: Uint32Array[number]): void;
/**
 * @param {Uint32Array} addr
 * @param {Uint32Array[number]} keyAndMask
 */
export function setKeyAndMask(addr: Uint32Array, keyAndMask: Uint32Array[number]): void;
/**
 * @param {Uint32Array} addr
 * @param {Uint32Array[number]} treeHeight
 */
export function setTreeHeight(addr: Uint32Array, treeHeight: Uint32Array[number]): void;
/**
 * @param {Uint32Array} addr
 * @param {Uint32Array[number]} treeIndex
 */
export function setTreeIndex(addr: Uint32Array, treeIndex: Uint32Array[number]): void;
/**
 * @param {Uint8Array} out
 * @param {Uint32Array[number]} input
 * @param {Uint32Array[number]} bytes
 */
export function toByteLittleEndian(out: Uint8Array, input: Uint32Array[number], bytes: Uint32Array[number]): void;
/**
 * @param {Uint8Array} out
 * @param {Uint32Array} addr
 * @param {function(): ENDIAN[keyof typeof ENDIAN]} getEndianFunc
 */
export function addrToByte(out: Uint8Array, addr: Uint32Array, getEndianFunc?: () => 0 | 1): void;
//# sourceMappingURL=helper.d.ts.map