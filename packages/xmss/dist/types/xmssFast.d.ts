/**
 * @param {HashFunction} hashFunction
 * @param {Uint8Array} seed
 * @param {Uint8Array} skSeed
 * @param {Uint32Array[number]} n
 * @param {Uint32Array} addr
 */
export function getSeed(hashFunction: HashFunction, seed: Uint8Array, skSeed: Uint8Array, n: Uint32Array[number], addr: Uint32Array): void;
/**
 * @param {HashFunction} hashFunction
 * @param {Uint8Array} outSeeds
 * @param {Uint8Array} inSeeds
 * @param {Uint32Array[number]} n
 * @param {Uint32Array[number]} len
 */
export function expandSeed(hashFunction: HashFunction, outSeeds: Uint8Array, inSeeds: Uint8Array, n: Uint32Array[number], len: Uint32Array[number]): void;
/**
 * @param {HashFunction} hashFunction
 * @param {Uint8Array} out
 * @param {Uint8Array} input
 * @param {Uint8Array} pubSeed
 * @param {Uint32Array} addr
 * @param {Uint32Array[number]} n
 */
export function hashF(hashFunction: HashFunction, out: Uint8Array, input: Uint8Array, pubSeed: Uint8Array, addr: Uint32Array, n: Uint32Array[number]): void;
/**
 * @param {HashFunction} hashFunction
 * @param {Uint8Array} out
 * @param {Uint8Array} input
 * @param {Uint32Array[number]} start
 * @param {Uint32Array[number]} steps
 * @param {WOTSParams} params
 * @param {Uint8Array} pubSeed
 * @param {Uint32Array} addr
 */
export function genChain(hashFunction: HashFunction, out: Uint8Array, input: Uint8Array, start: Uint32Array[number], steps: Uint32Array[number], params: WOTSParams, pubSeed: Uint8Array, addr: Uint32Array): void;
/**
 * @param {HashFunction} hashFunction
 * @param {Uint8Array} pk
 * @param {Uint8Array} sk
 * @param {WOTSParams} wOTSParams
 * @param {Uint8Array} pubSeed
 * @param {Uint32Array} addr
 */
export function wOTSPKGen(hashFunction: HashFunction, pk: Uint8Array, sk: Uint8Array, wOTSParams: WOTSParams, pubSeed: Uint8Array, addr: Uint32Array): void;
/**
 * @param {HashFunction} hashFunction
 * @param {WOTSParams} params
 * @param {Uint8Array} leaf
 * @param {Uint8Array} wotsPK
 * @param {Uint8Array} pubSeed
 * @param {Uint32Array} addr
 */
export function lTree(hashFunction: HashFunction, params: WOTSParams, leaf: Uint8Array, wotsPK: Uint8Array, pubSeed: Uint8Array, addr: Uint32Array): void;
/**
 * @param {HashFunction} hashFunction
 * @param {Uint8Array} leaf
 * @param {Uint8Array} skSeed
 * @param {XMSSParams} xmssParams
 * @param {Uint8Array} pubSeed
 * @param {Uint32Array} lTreeAddr
 * @param {Uint32Array} otsAddr
 */
export function genLeafWOTS(hashFunction: HashFunction, leaf: Uint8Array, skSeed: Uint8Array, xmssParams: XMSSParams, pubSeed: Uint8Array, lTreeAddr: Uint32Array, otsAddr: Uint32Array): void;
/**
 * @param {HashFunction} hashFunction
 * @param {BDSState} bdsState
 * @param {Uint32Array[number]} leafIdx
 * @param {Uint8Array} skSeed
 * @param {XMSSParams} params
 * @param {Uint8Array} pubSeed
 * @param {Uint32Array} addr
 */
export function bdsRound(hashFunction: HashFunction, bdsState: BDSState, leafIdx: Uint32Array[number], skSeed: Uint8Array, params: XMSSParams, pubSeed: Uint8Array, addr: Uint32Array): void;
/**
 * @param {BDSState} state
 * @param {XMSSParams} params
 * @param {TreeHashInst} treeHash
 * @returns {Uint8Array[number]}
 */
export function treeHashMinHeightOnStack(state: BDSState, params: XMSSParams, treeHash: TreeHashInst): Uint8Array[number];
/**
 * @param {HashFunction} hashFunction
 * @param {TreeHashInst} treeHash
 * @param {BDSState} bdsState
 * @param {Uint8Array} skSeed
 * @param {XMSSParams} params
 * @param {Uint8Array} pubSeed
 * @param {Uint32Array} addr
 */
export function treeHashUpdate(hashFunction: HashFunction, treeHash: TreeHashInst, bdsState: BDSState, skSeed: Uint8Array, params: XMSSParams, pubSeed: Uint8Array, addr: Uint32Array): void;
/**
 * @param {HashFunction} hashFunction
 * @param {BDSState} bdsState
 * @param {Uint32Array[number]} updates
 * @param {Uint8Array} skSeed
 * @param {XMSSParams} params
 * @param {Uint8Array} pubSeed
 * @param {Uint32Array} addr
 * @returns {Uint32Array[number]}
 */
export function bdsTreeHashUpdate(hashFunction: HashFunction, bdsState: BDSState, updates: Uint32Array[number], skSeed: Uint8Array, params: XMSSParams, pubSeed: Uint8Array, addr: Uint32Array): Uint32Array[number];
//# sourceMappingURL=xmssFast.d.ts.map