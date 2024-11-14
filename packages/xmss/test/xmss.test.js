import { expect } from 'chai';
import { newBDSState, newWOTSParams, newXMSSParams } from '../src/classes.js';
import { HASH_FUNCTION } from '../src/constants.js';
import {
  calcBaseW,
  calculateSignatureBaseSize,
  getSignatureSize,
  hMsg,
  wotsSign,
  xmssFastSignMessage,
} from '../src/xmss.js';
import { getUInt32ArrayFromHex, getUInt8ArrayFromHex } from './testUtility.js';

describe('Test cases for [xmss]', () => {
  describe('calcBaseW', () => {
    it('should calculate the base w, with w[6] input[4a4a...]', () => {
      const n = 13;
      const w = 6;
      const wotsParams = newWOTSParams(n, w);
      const outputLen = wotsParams.len1;
      const output = new Uint8Array(wotsParams.len);
      const input = getUInt8ArrayFromHex('4a4a20100cbd6e27a915b86f3b9e84fbcde1592d75515c8f52aaee9c4b');
      const expectedWotsParams = newWOTSParams(n, w);
      const expectedOutputLen = expectedWotsParams.len1;
      const expectedOutput = getUInt8ArrayFromHex(
        '010400000104000000000000000104000000010400010505010401040000010500000001000105050001040001040105000104010000000000'
      );
      const expectedInput = getUInt8ArrayFromHex('4a4a20100cbd6e27a915b86f3b9e84fbcde1592d75515c8f52aaee9c4b');
      calcBaseW(output, outputLen, input, wotsParams);

      expect(wotsParams).to.deep.equal(expectedWotsParams);
      expect(outputLen).to.deep.equal(expectedOutputLen);
      expect(output).to.deep.equal(expectedOutput);
      expect(input).to.deep.equal(expectedInput);
    });

    it('should calculate the base w, with w[16] input[2217...]', () => {
      const n = 25;
      const w = 16;
      const wotsParams = newWOTSParams(n, w);
      const outputLen = wotsParams.len1;
      const output = new Uint8Array(wotsParams.len);
      const input = getUInt8ArrayFromHex('221742170407081722174217040708172217421704070817221742170407081722');
      const expectedWotsParams = newWOTSParams(n, w);
      const expectedOutputLen = expectedWotsParams.len1;
      const expectedOutput = getUInt8ArrayFromHex(
        '0202010704020107000400070008010702020107040201070004000700080107020201070402010700040007000801070202000000'
      );
      const expectedInput = getUInt8ArrayFromHex('221742170407081722174217040708172217421704070817221742170407081722');
      calcBaseW(output, outputLen, input, wotsParams);

      expect(wotsParams).to.deep.equal(expectedWotsParams);
      expect(outputLen).to.deep.equal(expectedOutputLen);
      expect(output).to.deep.equal(expectedOutput);
      expect(input).to.deep.equal(expectedInput);
    });

    it('should calculate the base w, with w[256] input[9fca...]', () => {
      const n = 11;
      const w = 256;
      const wotsParams = newWOTSParams(n, w);
      const outputLen = wotsParams.len1;
      const output = new Uint8Array(wotsParams.len);
      const input = getUInt8ArrayFromHex('9fcad354487714f057dd96f113321010d43d23cc59a3e4d40aad2c92295f8348');
      const expectedWotsParams = newWOTSParams(n, w);
      const expectedOutputLen = expectedWotsParams.len1;
      const expectedOutput = getUInt8ArrayFromHex('9fcad354487714f057dd960000');
      const expectedInput = getUInt8ArrayFromHex('9fcad354487714f057dd96f113321010d43d23cc59a3e4d40aad2c92295f8348');
      calcBaseW(output, outputLen, input, wotsParams);

      expect(wotsParams).to.deep.equal(expectedWotsParams);
      expect(outputLen).to.deep.equal(expectedOutputLen);
      expect(output).to.deep.equal(expectedOutput);
      expect(input).to.deep.equal(expectedInput);
    });
  });

  describe('wotsSign', () => {
    it('should throw an error if the size of addr is invalid', () => {
      const hashFunction = HASH_FUNCTION.SHA2_256;
      const sig = getUInt8ArrayFromHex('e0c9f68aa304ec65958dc6c83498dd3307a5cd174282998b9ea495f1');
      const msg = getUInt8ArrayFromHex('8bac962de7f4e8b257424499c12b8f9faefc620cc4dd6b7a61ae');
      const sk = getUInt8ArrayFromHex('44ac8c8d2928fc2c76c5b568355fd9ba772483ce39');
      const n = 2;
      const w = 16;
      const params = newWOTSParams(n, w);
      const pubSeed = getUInt8ArrayFromHex('e80ad1787ef276fda4d00f46286f8eef9a7b60bdb0ca03d594ed26f195ee151a0a');
      const addr = getUInt8ArrayFromHex('883fd671d62de1');

      expect(() => wotsSign(hashFunction, sig, msg, sk, params, pubSeed, addr)).to.throw(
        'addr should be an array of size 8'
      );
    });

    it('should sign wots, with SHA2_256 n[2] w[16]', () => {
      const hashFunction = HASH_FUNCTION.SHA2_256;
      const sig = getUInt8ArrayFromHex('e0c9f68aa304ec65958dc6c83498dd3307a5cd174282998b9ea495f1');
      const msg = getUInt8ArrayFromHex('8bac962de7f4e8b257424499c12b8f9faefc620cc4dd6b7a61ae');
      const sk = getUInt8ArrayFromHex('44ac8c8d2928fc2c76c5b568355fd9ba772483ce39');
      const n = 2;
      const w = 16;
      const params = newWOTSParams(n, w);
      const pubSeed = getUInt8ArrayFromHex('e80ad1787ef276fda4d00f46286f8eef9a7b60bdb0ca03d594ed26f195ee151a0a');
      const addr = getUInt8ArrayFromHex('88f33fd671d62de1');
      const expectedSig = getUInt8ArrayFromHex('428fad3327fb17f987df25883498dd3307a5cd174282998b9ea495f1');
      const expectedMsg = getUInt8ArrayFromHex('8bac962de7f4e8b257424499c12b8f9faefc620cc4dd6b7a61ae');
      const expectedSk = getUInt8ArrayFromHex('44ac8c8d2928fc2c76c5b568355fd9ba772483ce39');
      const expectedParams = newWOTSParams(n, w);
      const expectedPubSeed = getUInt8ArrayFromHex(
        'e80ad1787ef276fda4d00f46286f8eef9a7b60bdb0ca03d594ed26f195ee151a0a'
      );
      const expectedAddr = getUInt8ArrayFromHex('88f33fd671050b01');
      wotsSign(hashFunction, sig, msg, sk, params, pubSeed, addr);

      expect(sig).to.deep.equal(expectedSig);
      expect(msg).to.deep.equal(expectedMsg);
      expect(sk).to.deep.equal(expectedSk);
      expect(params).to.deep.equal(expectedParams);
      expect(pubSeed).to.deep.equal(expectedPubSeed);
      expect(addr).to.deep.equal(expectedAddr);
    });

    it('should sign wots, with SHAKE_128 n[2] w[6]', () => {
      const hashFunction = HASH_FUNCTION.SHAKE_128;
      const sig = getUInt8ArrayFromHex('0808020d040e000505070b0c020b0a0b0e00040b0d0208070c097a1a31b20f48e4');
      const msg = getUInt8ArrayFromHex('b268b014fdebd6097a1a31b20f48e4e2093869285dbd9b1702');
      const sk = getUInt8ArrayFromHex('723645967f189a4acbc6658a1ae9a089e0026c4b8da6efac');
      const n = 2;
      const w = 6;
      const params = newWOTSParams(n, w);
      const pubSeed = getUInt8ArrayFromHex('d92bc3e4eb84ef64bad2fc17002fb3ce967363311abb8086656ef64d2045e0a6ab82');
      const addr = getUInt8ArrayFromHex('fdd7cf90409b661f');
      const expectedSig = getUInt8ArrayFromHex('e6d5d72c3a90e8f7392286c5658dabd92b0e64f2765c08070c097a1a31b20f48e4');
      const expectedMsg = getUInt8ArrayFromHex('b268b014fdebd6097a1a31b20f48e4e2093869285dbd9b1702');
      const expectedSk = getUInt8ArrayFromHex('723645967f189a4acbc6658a1ae9a089e0026c4b8da6efac');
      const expectedParams = newWOTSParams(n, w);
      const expectedPubSeed = getUInt8ArrayFromHex(
        'd92bc3e4eb84ef64bad2fc17002fb3ce967363311abb8086656ef64d2045e0a6ab82'
      );
      const expectedAddr = getUInt8ArrayFromHex('fdd7cf90400a0301');
      wotsSign(hashFunction, sig, msg, sk, params, pubSeed, addr);

      expect(sig).to.deep.equal(expectedSig);
      expect(msg).to.deep.equal(expectedMsg);
      expect(sk).to.deep.equal(expectedSk);
      expect(params).to.deep.equal(expectedParams);
      expect(pubSeed).to.deep.equal(expectedPubSeed);
      expect(addr).to.deep.equal(expectedAddr);
    });

    it('should sign wots, with SHAKE_256 n[3] w[256]', () => {
      const hashFunction = HASH_FUNCTION.SHAKE_256;
      const sig = getUInt8ArrayFromHex('5e290e7a1b1a670de199a4ec954bfd3b72aca3e6a1954c09e7f08d');
      const msg = getUInt8ArrayFromHex('227a5312705cd86531b825773e71df32a24a4317f567b8821b9c99c420304182cf40e2');
      const sk = getUInt8ArrayFromHex('0bc66b3b21b295151d9e1f9afbdc43d51f1d8cb87a59f08481b6768c9b3b');
      const n = 3;
      const w = 256;
      const params = newWOTSParams(n, w);
      const pubSeed = getUInt8ArrayFromHex('f0a9a5450914063f8454a81a4c3f3ddcccf029fcc5e107f6b9');
      const addr = getUInt8ArrayFromHex('0dd7426a623769b7');
      const expectedSig = getUInt8ArrayFromHex('a3d28fd861260b43f56352ef0fd1e63b72aca3e6a1954c09e7f08d');
      const expectedMsg = getUInt8ArrayFromHex(
        '227a5312705cd86531b825773e71df32a24a4317f567b8821b9c99c420304182cf40e2'
      );
      const expectedSk = getUInt8ArrayFromHex('0bc66b3b21b295151d9e1f9afbdc43d51f1d8cb87a59f08481b6768c9b3b');
      const expectedParams = newWOTSParams(n, w);
      const expectedPubSeed = getUInt8ArrayFromHex('f0a9a5450914063f8454a81a4c3f3ddcccf029fcc5e107f6b9');
      const expectedAddr = getUInt8ArrayFromHex('0dd7426a62040d01');
      wotsSign(hashFunction, sig, msg, sk, params, pubSeed, addr);

      expect(sig).to.deep.equal(expectedSig);
      expect(msg).to.deep.equal(expectedMsg);
      expect(sk).to.deep.equal(expectedSk);
      expect(params).to.deep.equal(expectedParams);
      expect(pubSeed).to.deep.equal(expectedPubSeed);
      expect(addr).to.deep.equal(expectedAddr);
    });
  });

  describe('calculateSignatureBaseSize', () => {
    it('should return the signature base size for the keysize 65', () => {
      const [keySize] = getUInt32ArrayFromHex('00000041');
      const signautreBaseSize = calculateSignatureBaseSize(keySize);
      const expectedSignatureBaseSize = 101;

      expect(signautreBaseSize).to.equal(expectedSignatureBaseSize);
    });

    it('should return the signature base size for the keysize 399', () => {
      const [keySize] = getUInt32ArrayFromHex('0000018f');
      const signautreBaseSize = calculateSignatureBaseSize(keySize);
      const expectedSignatureBaseSize = 435;

      expect(signautreBaseSize).to.equal(expectedSignatureBaseSize);
    });

    it('should return the signature base size for the keysize 1064', () => {
      const [keySize] = getUInt32ArrayFromHex('00000428');
      const signautreBaseSize = calculateSignatureBaseSize(keySize);
      const expectedSignatureBaseSize = 1100;

      expect(signautreBaseSize).to.equal(expectedSignatureBaseSize);
    });
  });

  describe('getSignatureSize', () => {
    it('should return the signature size for the n[2] h[4] w[6] k[8]', () => {
      const n = 2;
      const h = 4;
      const w = 6;
      const k = 8;
      const params = newXMSSParams(n, h, w, k);
      const signatureSize = getSignatureSize(params);
      const expectedSignatureSize = 186;

      expect(signatureSize).to.equal(expectedSignatureSize);
    });

    it('should return the signature size for the n[13] h[7] w[16] k[3]', () => {
      const n = 13;
      const h = 7;
      const w = 16;
      const k = 9;
      const params = newXMSSParams(n, h, w, k);
      const signatureSize = getSignatureSize(params);
      const expectedSignatureSize = 637;

      expect(signatureSize).to.equal(expectedSignatureSize);
    });

    it('should return the signature size for the n[25] h[13] w[256] k[9]', () => {
      const n = 25;
      const h = 13;
      const w = 256;
      const k = 9;
      const params = newXMSSParams(n, h, w, k);
      const signatureSize = getSignatureSize(params);
      const expectedSignatureSize = 1127;

      expect(signatureSize).to.equal(expectedSignatureSize);
    });
  });

  describe('hMsg', () => {
    it('should return an error if key length is not equal to 3 times n', () => {
      const hashFunction = HASH_FUNCTION.SHAKE_128;
      const out = getUInt8ArrayFromHex('22380207082d');
      const input = getUInt8ArrayFromHex('202d0708170507');
      const key = getUInt8ArrayFromHex('22380207082d22380202');
      const n = 3;
      const error = hMsg(hashFunction, out, input, key, n);

      expect(error).to.deep.equal({
        error: `H_msg takes 3n-bit keys, we got n=${n} but a keylength of ${key.length}.`,
      });
    });

    it('should return an null error if the function is executed correctly', () => {
      const hashFunction = HASH_FUNCTION.SHAKE_128;
      const out = getUInt8ArrayFromHex('22380207082d');
      const input = getUInt8ArrayFromHex('202d0708170507');
      const key = getUInt8ArrayFromHex('22380207082d223802');
      const n = 3;
      const error = hMsg(hashFunction, out, input, key, n);

      expect(error).to.deep.equal({
        error: null,
      });
    });
  });

  describe('xmssFastSignMessage', () => {
    it('should return sigMsg after signing the message, with message[743e...]', () => {
      const hashFunction = HASH_FUNCTION.SHAKE_128;
      const n = 32;
      const height = 4;
      const w = 16;
      const k = 2;
      const params = newXMSSParams(n, height, w, k);
      const sk = getUInt8ArrayFromHex(
        'afa43eed4f4c08562bb46aa85f8b7abbc693d3d78b981aaa7cde1e2a8801b199911ae58774b628a681e6352ad24f42dade1a3a2cf4dca45ad6830711e7eeb9a2294b47b8ac37c330db4b47193a9845128979b423f2de40d9373e74d6b83a9dd4f5c667f692633c0230af7b2027a8d20abbe624ace702eb1cbf083d92f30e50fad89f2b2d'
      );
      const bdsState = newBDSState(height, n, k);
      const message = getUInt8ArrayFromHex('743e154f026c55f859e45c937a56ae12b7f1f230a4fa3e9502cd8dae81b09b00');
      const expectedParams = newXMSSParams(n, height, w, k);
      const expectedSk = getUInt8ArrayFromHex(
        'afa43eee4f4c08562bb46aa85f8b7abbc693d3d78b981aaa7cde1e2a8801b199911ae58774b628a681e6352ad24f42dade1a3a2cf4dca45ad6830711e7eeb9a2294b47b8ac37c330db4b47193a9845128979b423f2de40d9373e74d6b83a9dd4f5c667f692633c0230af7b2027a8d20abbe624ace702eb1cbf083d92f30e50fad89f2b2d'
      );
      const expectedBdsState = {
        auth: getUInt8ArrayFromHex(
          '0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        ),
        keep: getUInt8ArrayFromHex(
          '00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        ),
        nextLeaf: 0,
        retain: getUInt8ArrayFromHex('0000000000000000000000000000000000000000000000000000000000000000'),
        stack: getUInt8ArrayFromHex(
          '00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        ),
        stackLevels: getUInt8ArrayFromHex('0000000000'),
        stackOffset: 0,
        treeHash: [
          {
            h: 0,
            nextIdx: 0,
            stackUsage: 0,
            completed: 0,
            node: getUInt8ArrayFromHex('0000000000000000000000000000000000000000000000000000000000000000'),
          },
          {
            h: 0,
            nextIdx: 0,
            stackUsage: 0,
            completed: 0,
            node: getUInt8ArrayFromHex('0000000000000000000000000000000000000000000000000000000000000000'),
          },
        ],
      };
      const expectedMessage = getUInt8ArrayFromHex('743e154f026c55f859e45c937a56ae12b7f1f230a4fa3e9502cd8dae81b09b00');
      const expectedSigMsg = getUInt8ArrayFromHex(
        'afa43eed38355fc6d0e06c48c3c82671b0c01136cf98a965d9d813c16e35a29a02f239369e00fdd64a0a14f8e9591d8c544261a20044553d80c9384d98ce5a68daff6c55a11d1b1a8597fc41d860f8b96a770c4addf26845aad44953289370ab8b7bc7c32bd16f6accb0fb1715bb84c6cf35c10d438a2f51f5b6918099cff9c73256bbef15dbb229fe6cbe8a192f387bb4cbd5755824177fff9d3c16a493f99e3b2eab5d10b2b75dd5eea5d289427910633ad1625fc3dbc1a51a723c5cfe8488ee909764ada9f07539702e3dcfd72e7d2b4afcea1bfdca3cf93d11e7b9feec49bbe655cc181309a783710f12d8c8492370dfcc0cbf6e8c98be4340c7d1b528d478253eb01349788c8a6ff7242927544c683f0d883be3c23503466077b7a80330529f416cb0a274f636be4555bfc913dfec7324ee95dfae22b94447a22d9e9a98d2c3ba1d0b974a5884707cb2392270645515d7c2cff029bf46cecd5d5a81978553d93d35fe70a2f7a14331686658122fe3adbb40558d8ccee49a53485167ed16363c856ddb71c28a9893eca7b41e0be179f2ee874d78d7cd31b48650e0df3f4b3d0723a48eaa2f7b5c771811ae08969164cbe31d7bfad30cb4a1c69f687d3243adf2effdfe8155d30f688ace6fc456d3eee90c5728a36a31cf60198c7d187ff8f55c205ae901553ad3234347cdb65c712dfcea8e76241d7d7b87a0d53cdc0a26a0a2f65182b6b289ec1b103dcf1da0589aa386a5097904761bc45ddcb62d4f70f4df17e4a5084999d12fd210d3a6c9f7be335f36fa6f83ca346f60b81ba266b04a0c1f95a418c0adae2245513d9ae13773fff2fc8343069fbd1bcfdc2e5778a81f2f0eaafc96bb9584c644a9f9a95647d161c62385f6262364fa8252557b75a157241ad85a8aff2555ba760047fcf7345b09bc03477abb952f7ca6873187c4663f24dcd54d973ae331de1188f416bee62f299389c38cb8df2e92882f153b812c607bb81bf4d8b4ce054d8a2771629227114455962777f26289b8fa8e3c38f800c26cb85e5605e1702ca0a9803a5941613c96051c78119a4fbcb954f8e63a524548dbed147f18567617712ed0b27958af7ecb1b2cfe105276525deb73cd8ab9b2043ad0c84ade85bb7065f3b9bdc13009bb7ae078eb85aacdd016063eef34687df2b11b59e598870054368da4fd61efe07a46f77c4b8c35f8928c8580c9998963fe0469909e90abdc654709579aeaee0687e1c99647faad5b845138de9aa9eee98f2058e33a5b351be2c7b78c2667e6d6d728ed01719a4a401dd5a963fbdfad50a6f80bd14d85abb77f0dd44b728ff0739c23e9212286e7bc5ff5610965a6bb1767ff90634a8df74e4de4dc0e677a0ef16dfdc64970cffdb1b83e792d661d478350437d1b357d8ba0158669cdfdacf680a989c0674dc846bb4f1284d7801e95b60b1801d10f9c8300f4b39f86ed4eedc3713c7ae975ed411b2200ea6bba357ed1ea1098fe9b14476b42d0def85b93266386a2060d46be72478822a8153290e944b92bafb0f6b1ccc86125128d5f26ba6eee0efeba6f84290ef2de889f3314dfe7d029a38b3e8aa52f517bfd865a4264533fc0bc6138d40b491cc4b0c8afb3d86d1d1c0064d876760dd75de752f799787f7acdf20364e00b9704fcf248d2eed96b77e3760dd5211eae89aa9a398ea54a85b0682838794ac5a7a4d500c209f64913177b0fe99947c0270a99ad3012eb21b3151859a7dea8f16b2404358e3c4971ac8583ee674e5c33697ef2dce93675e8a030ea467ea8623e96ba6897f03b1061e9c78a9e451bc75f1d79a2625a265bf5f72b7e493b58b2ed32be19ba1ff091b06e54205823a12270c93ac09a6d8ae96a13f6ed578b1064415576e0f5db9a3ae45f742203a383fd075d0466c4a0a58739d3b41f9e5a7ebb6b090097c4baf7cf9ec60204c5a6647015da8c9c4b70723349e4caf99469af7a3dadc6119cfa9ba2e86c946fd38b0838b6aa6e3c2c903c55df2c362461197678da9520a00a6be4f739d6d58edc94d360e9a4749fcb42cc76780479449f21a0a0b840cc9045dc80cf41d00dcdb8d67920cec451ba2a008f8996cfedd225f949f623334bcf51279089d0f1710786e0dbe75c79ff17c3e950867233046dee960781c7ce35e8e1c38b886b6227d8eed9903e0fe211c5f07e030c9d1bc15777eaa266ed02f170cc9910bbe8479909edee4c8ea62f70d03e324447d0ccd44ab465289154e2012897db46c307f6490f3a59e91b008906135d6b1769ad0f3c77aae4a7134f83ce0fca6057ca8e9765c5788ea400559ba4cf8fa5e7bca907f4bee952b75aaf5503a01474bad2c03dcc8bef199063a893b6daf9d354de92556fde23f69867d9b8573e2b746a9ce0691889bd1a5e9cdc487221161eab4c57babd24b0267ddbbd33ab1e1fbc7438da27038d72ab46b084b21865bb79b57891bf404bdd3e2cd51e629e3aa078b618262e6974e12c123775dd6fde9a0c739669902ef4a4ab465fd815a10ef4998bad21faf325cbbf322bff1fedae4c03f8b8d92bace8d2a6740692a76a03941e99550c82c95018c2b439d191360230a564467272e40410c1eb0c0102d07e6e6ea6e20e862b1f12e38891d0232de9389a486220e6b442bafe55591b36cbf6614ba291fa17b7e0f5fe77fb4a51b00b4de2d9be34b33e5ae280fe7eb428d7a38f6e3af6c74a23fcc218e29f311098e35d5b8385cb261a19b5bde227b9943867a967236b4b7376e78f9dfe3d5c5618b28c1012c144a1bc079650a4fd2d82ae25cef2594d3063d2c55fdf50aa8e64f7c805053a279e1687a27c338d5adf1e38092825cb0afc9b97906f4663b934b4fcaf9731c9d7f971a5c77593c24396b8f60098c45774eb4e3dc254fb9dbcca79230598deef356d7eef4265af9886c0ce8fdb6d8d7ed0e4c297fb76d2da82b1e2755da3beda0ca4c87fa276e20edda048e85d2ea42ecfc0c5a9c3724a5c0d4e55bb440e942585786d0f54fa232cb636ae7274a25e8f61272ea270e8d9428a90249ff62eecf822137ad014796d32302c496edad5e555e398fb44c9721c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
      );
      const { sigMsg, error } = xmssFastSignMessage(hashFunction, params, sk, bdsState, message);

      expect(params).to.deep.equal(expectedParams);
      expect(sk).to.deep.equal(expectedSk);
      expect(bdsState).to.deep.equal(expectedBdsState);
      expect(message).to.deep.equal(expectedMessage);
      expect(sigMsg).to.deep.equal(expectedSigMsg);
      expect(error).to.equal(null);
    });

    it('should return sigMsg after signing the message, with message[0000...]', () => {
      const hashFunction = HASH_FUNCTION.SHAKE_128;
      const n = 32;
      const height = 4;
      const w = 16;
      const k = 2;
      const params = newXMSSParams(n, height, w, k);
      const sk = getUInt8ArrayFromHex(
        '00000000eda313c95591a023a5b37f361c07a5753a92d3d0427459f34c7895d727d62816b3aa2224eb9d823127d4f9f8a30fd7a1a02c6483d9c0f1fd41957b9ae4dfc63a3191da3442686282b3d5160f25cf162a517fd2131f83fbf2698a58f9c46afc5dc25188b585f731c128e2b457069eafd1e3fa3961605af8c58a1aec4d82ac316d'
      );
      const bdsState = newBDSState(height, n, k);
      const message = getUInt8ArrayFromHex('0000000000000000000000000000000000000000000000000000000000000000');
      const expectedParams = newXMSSParams(n, height, w, k);
      const expectedSk = getUInt8ArrayFromHex(
        '00000001eda313c95591a023a5b37f361c07a5753a92d3d0427459f34c7895d727d62816b3aa2224eb9d823127d4f9f8a30fd7a1a02c6483d9c0f1fd41957b9ae4dfc63a3191da3442686282b3d5160f25cf162a517fd2131f83fbf2698a58f9c46afc5dc25188b585f731c128e2b457069eafd1e3fa3961605af8c58a1aec4d82ac316d'
      );
      const expectedBdsState = {
        auth: getUInt8ArrayFromHex(
          '3c89f5406198c1397ba5218f771a51549d5e6c62c58539c283189cbf02899fa6000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        ),
        keep: getUInt8ArrayFromHex(
          '00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        ),
        nextLeaf: 0,
        retain: getUInt8ArrayFromHex('0000000000000000000000000000000000000000000000000000000000000000'),
        stack: getUInt8ArrayFromHex(
          '00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        ),
        stackLevels: getUInt8ArrayFromHex('0000000000'),
        stackOffset: 0,
        treeHash: [
          {
            h: 0,
            nextIdx: 0,
            stackUsage: 0,
            completed: 1,
            node: getUInt8ArrayFromHex('3c89f5406198c1397ba5218f771a51549d5e6c62c58539c283189cbf02899fa6'),
          },
          {
            h: 0,
            nextIdx: 0,
            stackUsage: 0,
            completed: 0,
            node: getUInt8ArrayFromHex('0000000000000000000000000000000000000000000000000000000000000000'),
          },
        ],
      };
      const expectedMessage = getUInt8ArrayFromHex('0000000000000000000000000000000000000000000000000000000000000000');
      const expectedSigMsg = getUInt8ArrayFromHex(
        '0000000010ddfc3f7bfb9c95cc48f4cfac1eff2cbb03c0d0647e41a84de8d3ecebfe0bc25de56f7576ad9102ded6416dc48db619c7ed28e4de8f1a1fa4caa0efd9daed970c8e9f0f7de6e0a592af8fbbbe6495caa90291657ae3581857e216f3087ad0d00c9948edf953d8a34c4ac0cb9e6720085e30f8968f0f46d764841c42376b1f49920d5931da14880ff98f2400a65d1fef7c92f9395eb14f92607e49a0988247561e06ab0ac0e5658df3db83b6bef8ddc37ab4516d5cd60c0c644db78fb2d63e9c5d39ebf4128275174c668ddf9a52b25dc1cdfee39ed5452e07a7edcc3b7693c76e0b075e19fa8c275b9941b517655222532b63c18706cda97f4c32a07204687313509cfcaa0a64afa572ed1afa80aa485a805b456b28fa244d758e1fa2b32835eba53551b95c22e8800f0a895890da6436aaf25ee48b030741dfb6dded712d1df29c7e80aa1f70165ec8912966ce6666a6c3665b3450ec2e15e29e780f98b2ffec00dcd3aedc2d04a43ced47d1c52917a8528fa6a46c77acc227d68f546a12825fcdce1b2446fbbc7047337e8eec296d9259d75ff4b219d636d09823926ae57bc1d8e05780048d2775510244635d06f22c48ad299e006882ab7eed2b0c586314021a6813bf710cc1e7e31be9307fdcdda15e84d3ba853a029eb1732ff6a5560931fb7634ced4948e1046af949a95d5b3f3510e8921b7db04c9dfd8553537e7d8dd26a0c93438bb3ac396bed58ae3d96c19bdaa6a1bfa1cb8b3eeecc0458a1a37c4d779030fb44ba1020e79c56dceb443868702a07181f7740dc51477928da631b52b928d0b81c9a37a49a0a6311c16dd6229bac9d890ac8ff2d369d6c89d5638a87f3da2a2ed0887897d8e38b10189bcce896be4c26378f5f62a93a972db058d7f8025094b19d4ead94e804f35323a8891d80a879fa062cb3954d96c6451a768ca3073f689228c629b212dde2d64605d81b7f663cab4d0b56b9e43edc9a58f92b6a4a03dcdbe60fa43129e67844a867d350d668a2f3fcee26c92e5532105215fcb6e63e60c4bd9d73a3f61669ab872b4725690c6304d9bc6adcb3f564b180fe4acaa4a37cd4d018b3a0dc11653ac679434631d7b27247feca64a8a05d971d4b3238ce4217d4b290235b01e54b9de69fd01450679b164c45fcea8d873ea4bd0b0377d36506a98392e28fe81c525703da9e4a636ef4c1ac990b727869da2e54a8ed275752b8ed914d90bc685ce572a83032f04f266d8bb14f450917c91cc83c7e404ad2905cfbe4ea2e40b757c7e3e4097f6b4ac9157836b1ea4117fcecfb7524964f60455984c0574adffea289414dea5332c281fc658aee02d94859e0f935472358234dc9b8b6a44a84a843ddf08ca21c5c79966e7f5074c6dff2b040b4aafd58289d82ee1c1dbca20bb4fad1fea4700c729520c07d7d7e071d066d1dcb50fadef56a9a56eca9b09482f05138f4d2259839c80ae1eb3f10e27233f8761cd7a6786924d6cefa7aecb610dc146ed92a6ec9d34b4175cd13bc54f202084fa4c5b81b9cb846cba0d501edac1dc9da8c13db53abf61286b5da7c1d6ecb29e2ed4aea9057e687707d69884b61686894d093e2ce15b825188602d9f00f9513dbf3b2c2fd9b0bde3b8313556c3c981cb70c583879cfd2b2e8d67cd4c8749a8ee29d42bdac9cd5ff44d8375c495fec0780051d805e5e62612393b24ea292324c9d458517ca5cf06f9bac9ddc84d03d20c79ff8d54df297c4b630d5fd19e75621e7526916740065c4fc74a2466c32c6d9f0d9c4dee6b6cc40c4e35e77d79a72ec1566541823e0acbd31022ceafd58710289ac0699ed6e25186638c37979a0e57f2db0d6139608b6bff3b48d62ba87379f642a002561dc38abdc9b799e0c2d0356f714914f4d4316e3ba770c4ab7e30c22be0a0b920f1324bedeb283e202a9daf87b4959cb11617a1f64d328128428fc7cc7947bfe15259fd11a8bb663916a28891dec8334c1547d37151a05fddfde0190ada322dbe9ddb83eb0595b2751827782b9ee78e3e90a01f1421279fcd0dcf10969d18633c4ba43cbf2a8364fa22c3295d471adc41651d0bcf36751fe49e146cb85d5f3f9b9c6730bedc6388e638d1e65c81f9254dd62ba8264c1ae016f9cd33ba50a157763ca3d17491b6a487d6398bce9ec36882aef84d0cc078ddb329aef1962c86af39256bc65ab926526ea8d7b290baadf2145d4e0acaf30c24fd6d603c1b3cff1a6c51ff41e4ab5f61acbd0bfd0cc23c18a684e40ca5f1162b08c241956792855ea29712c79ffbeb04df32d027fb68da3b667515c051a40715a6781ecc0313fc91e8d44b8efece69b2c5331dfa13a9061155326d106a21b3c20b84e0c8b2f9ba7017b66434ecbb9f2dd6faefc67cdae962fd9f74093b52c9e32891b190840cd6333fe4e4bf59508529e5ab3b5b1aba83565ff5d47a3a07b55abaf2a462ae06cfe7e72bf4a18703e3c2a840f3fd1f263614db72f0d4e8391e348b11718319324e8d16537d179bfcb038997555b67deae186819a61ae6297af9db1e313eeaa9b58c3b2b7918f1ee34c4461e8912dd2944abf254e9a2e36a99c392065408b031251ff0895b7e7231d475852f6d51ac450f491ac76cb8dad053b511a17fcf39981165670ae5eab6118c506bc1c67c035e525dd23cc6448d7b8bc2b0cc21a2d30167d43cc8fe6c6373a041b2a2d720dce845be178cd51e81f2eb6931fcd1e63778550600e91585cc832bf4d22157badc5bb0da1e12fa0a03735f03f38751c0bc64ce04905071b76d9cce03eeec0eefe821a028f4d18dfb2e8d11563c6eec1b08ae78118ac3d62d79540ecec0e11f9fc5f51d2fb3867eea45c1fb0d9f03a30d1798615cbba470ebb6028103809d504cacac26cfb583dbcb1104aadde5b332b6938832ef91f57c8425882c27da1fc8a573f1d9ac38798f5808624d64c95caa2b1009ab5d1ba35b03d43afea31cd4bed53ab57ea8c6009a204b0d30e0ad633a436a2b716860184919063ce5addac04347a1beba3d03e41ed6ffc58a917b13fb64f1f36c5f7244dfbfa5465ab9e5dde9d41b875f230140000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
      );
      const { sigMsg, error } = xmssFastSignMessage(hashFunction, params, sk, bdsState, message);

      expect(params).to.deep.equal(expectedParams);
      expect(sk).to.deep.equal(expectedSk);
      expect(bdsState).to.deep.equal(expectedBdsState);
      expect(message).to.deep.equal(expectedMessage);
      expect(sigMsg).to.deep.equal(expectedSigMsg);
      expect(error).to.equal(null);
    });

    it('should return sigMsg after signing the message, with message[68bc...]', () => {
      const hashFunction = HASH_FUNCTION.SHAKE_256;
      const n = 32;
      const height = 4;
      const w = 16;
      const k = 2;
      const params = newXMSSParams(n, height, w, k);
      const sk = getUInt8ArrayFromHex(
        'b10217cf714044a891a19f3c17b2675010e05d5ea84a96b181926995df5bbddb523b76517fa322cf5ec537fc6a7f74a6f0110f996fc65a6a9bd5f2b8aa57aa68d5ce03e4deb53ed6d976a317d03b250e8702f68d9e5d0a41c5ac6c5ecbf14eb6da7228aecfc651808cdd9fe8a1377d907837a2c092e12ac8083a55de904f54b292c40867'
      );
      const bdsState = newBDSState(height, n, k);
      const message = getUInt8ArrayFromHex('68bc27593ec688464622c15e820e54566e1c97f6ca4fb4ac769e30931fee1952');
      const expectedParams = newXMSSParams(n, height, w, k);
      const expectedSk = getUInt8ArrayFromHex(
        'b10217d0714044a891a19f3c17b2675010e05d5ea84a96b181926995df5bbddb523b76517fa322cf5ec537fc6a7f74a6f0110f996fc65a6a9bd5f2b8aa57aa68d5ce03e4deb53ed6d976a317d03b250e8702f68d9e5d0a41c5ac6c5ecbf14eb6da7228aecfc651808cdd9fe8a1377d907837a2c092e12ac8083a55de904f54b292c40867'
      );
      const expectedBdsState = {
        auth: getUInt8ArrayFromHex(
          '0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        ),
        keep: getUInt8ArrayFromHex(
          '00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        ),
        nextLeaf: 0,
        retain: getUInt8ArrayFromHex('0000000000000000000000000000000000000000000000000000000000000000'),
        stack: getUInt8ArrayFromHex(
          '00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        ),
        stackLevels: getUInt8ArrayFromHex('0000000000'),
        stackOffset: 0,
        treeHash: [
          {
            h: 0,
            nextIdx: 0,
            stackUsage: 0,
            completed: 0,
            node: getUInt8ArrayFromHex('0000000000000000000000000000000000000000000000000000000000000000'),
          },
          {
            h: 0,
            nextIdx: 0,
            stackUsage: 0,
            completed: 0,
            node: getUInt8ArrayFromHex('0000000000000000000000000000000000000000000000000000000000000000'),
          },
        ],
      };
      const expectedMessage = getUInt8ArrayFromHex('68bc27593ec688464622c15e820e54566e1c97f6ca4fb4ac769e30931fee1952');
      const expectedSigMsg = getUInt8ArrayFromHex(
        'b10217cfb68feab85b43a8bb0b99d1f5c21784a6669c6198d58d7eae1c3614365f942e1ba971b9ff4499a52452ec0e1fcee17fcf6205af0058fb5614c862029efd1207a592c8a8ca432e6366d785bf1a3f250d730d585b451d6ad07dcc2e03cb4d436500f3ebffc9b70df3fda22089243739a20b274ab60d3e0fda3da74eaa570c05b2230063c5de3d9d6aa5d7db3676f746ccf8464c6543aad87b57364c94f297040f69efab3016303aba168e39aadd3324efeec6ec6b6f3b028908ab4e2684146929c2d65158b31690b074f6caccbd697e6791bc894d90666690df741cfb1a4e91204375b97fc172c843360cacc5f21be796074646df579a4d6d52144e2b0d4c0b5ecf00b7e19607c6fb2501484e6bf172e94247b2af5a73803dafff9a21c86a603c4e08a9355ac0b5de8ff7a1ef823ea2c66eec81e91260aee05cdde02b5f4a347e16bd747fc609e62c91939081c6e0faa904a77ee5763be8057d17d8dc68cff7c0792ab0b6648fa63cbed273db2085019a9ef66124dea5c0158624073e9392d3d5bc683280b0ca51de896c1bb0ecefdbd6a851704ae492fe188f056e87ac7ca200d43828dafad11e647861c98bdbc9d1d7e041144a0a56495321b16a09d4b3e373a3f15cedff5db3eabd32a0d0d65c62b86f575dc32ef550a1ef2fc3a4da624a6b50df9ee7a6fe41eff18241478c47b609dde603c56bdc4ff95a3199d0afa8d6c1997817966cc497e3428d9e902962c1e914186da0254d9d9e4a10ef7ef47ead8215d4a60b49c9d4e7508bf36c96d5b553abbeb517d83e8cef4da4c671a92d4d075640eace6912b2466f45d95f5260a9e4de5764b771c396393467619cb59d370e71ebe41e4f9414aa773b5800299a20f7f207e0230ca1b05b89a099c576f3782557ec1b3734181a42a92a96b90d93b3803a7d44247217ebff80e0d0ae41fd0e26a6e56cffa07acc5aecfb833d9aca96b57bf4716848c1069bdbdc85fa3729c518f5434e05fb6d1f26f7fb751ca2ed5ab7167c8cf77076656a96e02ddbc2d8b4279e676e4b9cd72f2fa59e2d698cd733a468ab4d35a44c8c2eb12a76d6e4686ee393938c52d5964157bb8593306e0e96e3bc52a32e6d9b2349200674b93e253e06331e35564cd89c8284097b8e7e1d35db7a337a3ef449a28101063c37d019046c4129489d155ec2d5b9227aeadb194af156a3c04d412ad44132454a0dcecc322d55d693d6ad5267f3489783111fe922eccdbb70ac2899315ffa58525b2273a746d892dcf895fd5127020d8684c6b09cc98cd3d2f146ad519896caa33835fe12b8ad66eb7644ea26bd1a8510d268f76fa2de8de18e59f4ad7ec618d4bf8942a5241b8f436d92559e3824a51513029f607bc8e6b151417a84cafd78b0c91e058ebf6542b276f9d4cbdf207c823bdec310a3188b3df3fa05e5dbcc9a6b982c6a8eec1fac9c6d754e767c3b53df0ac55b7805ea1083c05475c0f94ece557a12d255b68c947e4ac41d3a8e7dcdb6ead352a307494ae4aaa3908aa969319a80803ad1704d65c9ab309317cdd87ca09521715baf75fd6b6fb95424b2ec519202081452ca9a79c342a45152163d46831dc9471b814a98c4cb186c540a90df1e4ed89882b2c3acb90e8e5f6590e9022ea91ff09f73887b2d684131b49b393c6b60bda610fa0b668fcc51dd729010f1fce271747e98614eff3dddb20ca5f1a98b600978982ba05134ee02c83f693c403b8113435e67e60022513dd912afee0be3453a4fa0d12e0fa90b1e44e8a713f04e9309d74c2ee3b39f2b7164a23d07dd14af03a66274802a7f0345d39dd7f69f442c0f8e84504b0f95bf3522da99572ad2074bf18dc3ae83a83dd63b2a70c674ad4d4cd63c54cac706728e70a2928ed5af8fa8dffead16a6c24a966818ffabe612e2ab5f355f501bd2c0a52661f95f49aa62df82303e00e568db1709719c815db69d066462da6f65199918c23dfe3a2efb0b6af994d456ca4a47a6d2cccf3cb6a1001655baa3e9e41343b725d39b1f19050fd30813e6edae9b67f078035c45c6ad9b27262fd052dc9517bb4120ed6378281956a5ca8308a4f70ba1d972c1857cd217a6f3cc8c6f56248654a099b7fa47b5e64af0540b670268e526036649aedf036bf332e87b2287b13a96905956addad694ecb4e3b764c7541fb4b88d0ca9b77d0205f8903feab2da401882e05d1a6457c20636b2956df65572fe7f50741ccef08e155c11cdffceb858d90404105e5b1bcbef142ba6c621e183959ebe587ce596de15e132f8bc9c7626ec561285b739bdb5ec5a4a98c1ca23802f9bb756311db219a22308f0b44856887b9b0076061dbdbfa2a6d2ccd2158a57b1138ab99f1199998e186fbbf094a1e950914471f05d4797666d39748fdee34da0066810680b9705788658a0222f3b083579a787fd6a1cf2cf11ea10dfa9046e420f280f88896051ce5195567c74213815fe5cc24233cfb2a3626a774877f559081e0a182b8484e760e0e0f17cf7050f6186896fe89e01c1f87c18e0c8e20f7b587876c07f04e967ed4f52d42134fd1476a0a62197025cd8a66681d9addbee248b5e48330b2e8476574db08e340a7bdee3353710f6f809fad9bcc4fac10ea7a7be263abe14c498f7c4df580d61d325948fd4251d5b620adb60ae90054f3bb616acd5fb5dd4144e4f715ffa278c7429818556812ee6c6209d24039372fe429d16ae910eb0e61ab08125340d0289b756fa476097d239944b0429ab953025a81f9e092e773a37c1af74156251a593a658033d3be4128792e83dc6771cfc4aa58e71ffedfb2c76f830997f5b88d8805db98fabf943e0660cc825e86ddff8d87fa0b14379222e05d3fbbbc2634086720cf127dd0c92ac6f111c0a56f9fd15d80403c8670ea099daa7a085ef5c4cd5f4af4f8341442166c616461573a627821a696838ac1799600d03579dc1736b4cda203323367092521d0cd6bbab795a93c5a8e35436d177f04dbb0d721ed2775496f0c2575e92e30d0d067a97ff6584e41ce1c85094cf6285698c592339b6e959d940fec50184ccaebedd2073f41a6fb2570000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
      );
      const { sigMsg, error } = xmssFastSignMessage(hashFunction, params, sk, bdsState, message);

      expect(params).to.deep.equal(expectedParams);
      expect(sk).to.deep.equal(expectedSk);
      expect(bdsState).to.deep.equal(expectedBdsState);
      expect(message).to.deep.equal(expectedMessage);
      expect(sigMsg).to.deep.equal(expectedSigMsg);
      expect(error).to.equal(null);
    });
  });
});
