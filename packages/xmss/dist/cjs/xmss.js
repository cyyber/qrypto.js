'use strict';

var sha256$1 = require('@noble/hashes/sha256');
var jsSha3CommonJsPackage = require('js-sha3');

/// <reference path="typedefs.js" />

class TreeHashInstClass {
  constructor(n = 0) {
    [this.h] = new Uint32Array([0]);
    [this.nextIdx] = new Uint32Array([0]);
    [this.stackUsage] = new Uint32Array([0]);
    [this.completed] = new Uint8Array([0]);
    this.node = new Uint8Array(n);
  }
}

/**
 * @param {Uint32Array[number]} n
 * @returns {TreeHashInst}
 */
function newTreeHashInst(n) {
  return new TreeHashInstClass(n);
}

class BDSStateClass {
  constructor(height, n, k) {
    this.stackOffset = 0;
    this.stack = new Uint8Array((height + 1) * n);
    this.stackLevels = new Uint8Array(height + 1);
    this.auth = new Uint8Array(height * n);
    this.keep = new Uint8Array((height >>> 1) * n);
    this.treeHash = new Array(0);
    for (let i = 0; i < height - k; i++) {
      this.treeHash.push(newTreeHashInst(n));
    }
    this.retain = new Uint8Array(((1 << k) - k - 1) * n);
    this.nextLeaf = 0;
  }
}

/**
 * @param {Uint32Array[number]} height
 * @param {Uint32Array[number]} n
 * @param {Uint32Array[number]} k
 * @returns {BDSState}
 */
function newBDSState(height, n, k) {
  return new BDSStateClass(height, n, k);
}

class WOTSParamsClass {
  constructor(n, w) {
    this.n = n;
    this.w = w;
    [this.logW] = new Uint32Array([Math.log2(w)]);
    if (this.logW !== 2 && this.logW !== 4 && this.logW !== 8) {
      throw new Error('logW should be either 2, 4 or 8');
    }
    // an integer value is passed to the ceil function for now w.r.t. golang code. update this as and when required.
    [this.len1] = new Uint32Array([Math.ceil(parseInt(((8 * n) / this.logW).toString(), 10))]);
    [this.len2] = new Uint32Array([Math.floor(Math.log2(this.len1 * (w - 1)) / this.logW) + 1]);
    this.len = this.len1 + this.len2;
    this.keySize = this.len * n;
  }
}

/**
 * @param {Uint32Array[number]} n
 * @param {Uint32Array[number]} w
 * @returns {WOTSParams}
 */
function newWOTSParams(n, w) {
  return new WOTSParamsClass(n, w);
}

class XMSSParamsClass {
  constructor(n, h, w, k) {
    this.wotsParams = newWOTSParams(n, w);
    this.n = n;
    this.h = h;
    this.k = k;
  }
}

/**
 * @param {Uint32Array[number]} n
 * @param {Uint32Array[number]} h
 * @param {Uint32Array[number]} w
 * @param {Uint32Array[number]} k
 * @returns {XMSSParams}
 */
function newXMSSParams(n, h, w, k) {
  return new XMSSParamsClass(n, h, w, k);
}

const ENDIAN = Object.freeze({
  LITTLE: 0,
  BIG: 1,
});

const HASH_FUNCTION = Object.freeze({
  SHA2_256: 0,
  SHAKE_128: 1,
  SHAKE_256: 2,
});

const { shake256: sha3Shake256, shake128: sha3Shake128 } = jsSha3CommonJsPackage;

/**
 * @param {Uint8Array} out
 * @param {Uint8Array} msg
 * @returns {Uint8Array}
 */
function shake128(out, msg) {
  const hash = sha3Shake128(msg, 8 * out.length);
  for (let i = 0, h = 0; i < out.length; i++, h++) {
    out.set([parseInt(hash.substring(h * 2, h * 2 + 2), 16)], i);
  }
  return out;
}

/**
 * @param {Uint8Array} out
 * @param {Uint8Array} msg
 * @returns {Uint8Array}
 */
function shake256(out, msg) {
  const hash = sha3Shake256(msg, 8 * out.length);
  for (let i = 0, h = 0; i < out.length; i++, h++) {
    out.set([parseInt(hash.substring(h * 2, h * 2 + 2), 16)], i);
  }
  return out;
}

/**
 * @param {Uint8Array} out
 * @param {Uint8Array} msg
 * @returns {Uint8Array}
 */
function sha256(out, msg) {
  const hashOut = sha256$1.sha256(msg);
  for (let i = 0, h = 0; i < out.length && h < hashOut.length; i++, h++) {
    out.set([hashOut[h]], i);
  }
  return out;
}

/**
 * @param {Uint32Array} addr
 * @param {Uint32Array[number]} typeValue
 */
function setType(addr, typeValue) {
  addr.set([typeValue], 3);
  for (let i = 4; i < 8; i++) {
    addr.set([0], i);
  }
}

/**
 * @param {Uint32Array} addr
 * @param {Uint32Array[number]} lTree
 */
function setLTreeAddr(addr, lTree) {
  addr.set([lTree], 4);
}

/**
 * @param {Uint32Array} addr
 * @param {Uint32Array[number]} ots
 */
function setOTSAddr(addr, ots) {
  addr.set([ots], 4);
}

/**
 * @param {Uint32Array} addr
 * @param {Uint32Array[number]} chain
 */
function setChainAddr(addr, chain) {
  addr.set([chain], 5);
}

/**
 * @param {Uint32Array} addr
 * @param {Uint32Array[number]} hash
 */
function setHashAddr(addr, hash) {
  addr.set([hash], 6);
}

/**
 * @param {Uint32Array} addr
 * @param {Uint32Array[number]} keyAndMask
 */
function setKeyAndMask(addr, keyAndMask) {
  addr.set([keyAndMask], 7);
}

/**
 * @param {Uint32Array} addr
 * @param {Uint32Array[number]} treeHeight
 */
function setTreeHeight(addr, treeHeight) {
  addr.set([treeHeight], 5);
}

/**
 * @param {Uint32Array} addr
 * @param {Uint32Array[number]} treeIndex
 */
function setTreeIndex(addr, treeIndex) {
  addr.set([treeIndex], 6);
}

/** @returns Number */
function getEndian() {
  const buffer = new ArrayBuffer(2);
  const uint16View = new Uint16Array(buffer);
  const uint8View = new Uint8Array(buffer);
  uint16View[0] = 0xabcd;
  if (uint8View[0] === 0xcd && uint8View[1] === 0xab) {
    return ENDIAN.LITTLE;
  }
  if (uint8View[0] === 0xab && uint8View[1] === 0xcd) {
    return ENDIAN.BIG;
  }
  throw new Error('Could not determine native endian.');
}

/**
 * @param {Uint8Array} out
 * @param {Uint32Array[number]} input
 * @param {Uint32Array[number]} bytes
 */
function toByteLittleEndian(out, input, bytes) {
  let inValue = input;
  for (let i = bytes - 1; i >= 0; i--) {
    out.set([new Uint8Array([inValue & 0xff])[0]], i);
    inValue >>>= 8;
  }
}

/**
 * @param {Uint8Array} out
 * @param {Uint32Array[number]} input
 * @param {Uint32Array[number]} bytes
 */
function toByteBigEndian(out, input, bytes) {
  let inValue = input;
  for (let i = 0; i < bytes; i++) {
    out.set([new Uint8Array([inValue & 0xff])[0]], i);
    inValue >>>= 8;
  }
}

/**
 * @param {Uint8Array} out
 * @param {Uint32Array} addr
 * @param {function(): ENDIAN[keyof typeof ENDIAN]} getEndianFunc
 */
function addrToByte(out, addr, getEndianFunc = getEndian) {
  if (addr.length !== 8) {
    throw new Error('addr should be an array of size 8');
  }

  switch (getEndianFunc()) {
    case ENDIAN.LITTLE:
      for (let i = 0; i < 8; i++) {
        toByteLittleEndian(out.subarray(i * 4, i * 4 + 4), addr[i], 4);
      }
      break;
    case ENDIAN.BIG:
      for (let i = 0; i < 8; i++) {
        toByteBigEndian(out.subarray(i * 4, i * 4 + 4), addr[i], 4);
      }
      break;
    default:
      throw new Error('Invalid Endian');
  }
}

/// <reference path="typedefs.js" />


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
function coreHash(hashFunction, out, typeValue, key, keyLen, input, inLen, n) {
  const buf = new Uint8Array(inLen + n + keyLen);
  toByteLittleEndian(buf, typeValue, n);
  for (let i = 0; i < keyLen; i++) {
    buf.set([key[i]], i + n);
  }
  for (let i = 0; i < inLen; i++) {
    buf.set([input[i]], keyLen + n + i);
  }

  switch (hashFunction) {
    case HASH_FUNCTION.SHA2_256:
      sha256(out, buf);
      break;
    case HASH_FUNCTION.SHAKE_128:
      shake128(out, buf);
      break;
    case HASH_FUNCTION.SHAKE_256:
      shake256(out, buf);
      break;
  }
}

/**
 * @param {HashFunction} hashFunction
 * @param {Uint8Array} out
 * @param {Uint8Array} input
 * @param {Uint8Array} key
 * @param {Uint32Array[number]} keyLen
 */
function prf(hashFunction, out, input, key, keyLen) {
  coreHash(hashFunction, out, 3, key, keyLen, input, 32, keyLen);
}

/**
 * @param {HashFunction} hashFunction
 * @param {Uint8Array} out
 * @param {Uint8Array} input
 * @param {Uint8Array} pubSeed
 * @param {Uint32Array} addr
 * @param {Uint32Array[number]} n
 */
function hashH(hashFunction, out, input, pubSeed, addr, n) {
  if (addr.length !== 8) {
    throw new Error('addr should be an array of size 8');
  }

  const buf = new Uint8Array(2 * n);
  const key = new Uint8Array(n);
  const bitMask = new Uint8Array(2 * n);
  const byteAddr = new Uint8Array(32);

  setKeyAndMask(addr, 0);
  addrToByte(byteAddr, addr);
  prf(hashFunction, key, byteAddr, pubSeed, n);

  setKeyAndMask(addr, 1);
  addrToByte(byteAddr, addr);
  prf(hashFunction, bitMask.subarray(0, n), byteAddr, pubSeed, n);
  setKeyAndMask(addr, 2);
  addrToByte(byteAddr, addr);
  prf(hashFunction, bitMask.subarray(n, n + n), byteAddr, pubSeed, n);
  for (let i = 0; i < 2 * n; i++) {
    buf.set([input[i] ^ bitMask[i]], i);
  }
  coreHash(hashFunction, out, 1, key, n, buf, 2 * n, n);
}

exports.ENDIAN = ENDIAN;
exports.HASH_FUNCTION = HASH_FUNCTION;
exports.addrToByte = addrToByte;
exports.coreHash = coreHash;
exports.hashH = hashH;
exports.newBDSState = newBDSState;
exports.newTreeHashInst = newTreeHashInst;
exports.newWOTSParams = newWOTSParams;
exports.newXMSSParams = newXMSSParams;
exports.prf = prf;
exports.setChainAddr = setChainAddr;
exports.setHashAddr = setHashAddr;
exports.setKeyAndMask = setKeyAndMask;
exports.setLTreeAddr = setLTreeAddr;
exports.setOTSAddr = setOTSAddr;
exports.setTreeHeight = setTreeHeight;
exports.setTreeIndex = setTreeIndex;
exports.setType = setType;
exports.sha256 = sha256;
exports.shake128 = shake128;
exports.shake256 = shake256;
exports.toByteLittleEndian = toByteLittleEndian;
