/**
 * @param {Uint32Array[number]} n
 * @returns {TreeHashInst}
 */
export function newTreeHashInst(n: Uint32Array[number]): TreeHashInst;
/**
 * @param {Uint32Array[number]} height
 * @param {Uint32Array[number]} n
 * @param {Uint32Array[number]} k
 * @returns {BDSState}
 */
export function newBDSState(height: Uint32Array[number], n: Uint32Array[number], k: Uint32Array[number]): BDSState;
/**
 * @param {Uint32Array[number]} n
 * @param {Uint32Array[number]} w
 * @returns {WOTSParams}
 */
export function newWOTSParams(n: Uint32Array[number], w: Uint32Array[number]): WOTSParams;
/**
 * @param {Uint32Array[number]} n
 * @param {Uint32Array[number]} h
 * @param {Uint32Array[number]} w
 * @param {Uint32Array[number]} k
 * @returns {XMSSParams}
 */
export function newXMSSParams(n: Uint32Array[number], h: Uint32Array[number], w: Uint32Array[number], k: Uint32Array[number]): XMSSParams;
declare class TreeHashInst {
    constructor(n?: number);
    node: Uint8Array;
}
declare class BDSState {
    constructor(height: any, n: any, k: any);
    stackOffset: number;
    stack: Uint8Array;
    stackLevels: Uint8Array;
    auth: Uint8Array;
    keep: Uint8Array;
    treeHash: any[];
    retain: Uint8Array;
    nextLeaf: number;
}
declare class WOTSParams {
    constructor(n: any, w: any);
    n: any;
    w: any;
    len: any;
    keySize: number;
}
declare class XMSSParams {
    constructor(n: any, h: any, w: any, k: any);
    wotsParams: WOTSParams;
    n: any;
    h: any;
    k: any;
}
export {};
//# sourceMappingURL=classes.d.ts.map