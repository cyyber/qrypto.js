type WOTSParams = {
    len1: Uint32Array[number];
    len2: Uint32Array[number];
    len: Uint32Array[number];
    n: Uint32Array[number];
    w: Uint32Array[number];
    logW: Uint32Array[number];
    keySize: Uint32Array[number];
};
type XMSSParams = {
    wotsParams: WOTSParams;
    n: Uint32Array[number];
    h: Uint32Array[number];
    k: Uint32Array[number];
};
type HashFunction = Uint32Array[number];
type TreeHashInst = {
    h: Uint32Array[number];
    nextIdx: Uint32Array[number];
    stackUsage: Uint32Array[number];
    completed: Uint8Array[number];
    node: Uint8Array;
};
type BDSState = {
    stack: Uint8Array;
    stackOffset: Uint32Array[number];
    stackLevels: Uint8Array;
    auth: Uint8Array;
    keep: Uint8Array;
    treeHash: TreeHashInst[];
    retain: Uint8Array;
    nextLeaf: Uint32Array[number];
};
type SignatureReturnType = {
    sigMsg: Uint8Array | null;
    error: string | null;
};
//# sourceMappingURL=typedefs.d.ts.map