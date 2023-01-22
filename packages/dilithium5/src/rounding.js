import {D, GAMMA2, Q} from "./const.js";

export function power2round(a0, i, a) {
    let a1 = (a + (1 << (D-1)) - 1) >> D;
    a0[i] = a - (a1 << D);
    return a1;
}

export function decompose(a0, i, a) {
    let a1  = (a + 127) >> 7;
    a1  = (a1 * 1025 + (1 << 21)) >> 22;
    a1 &= 15;

    a0[i]  = a - a1 * 2 * GAMMA2;
    a0[i] -= (((Q - 1) / 2 - a0[i]) >> 31) & Q;
    return a1;
}

export function makeHint(a0, a1) {
    if(a0 > GAMMA2 || a0 < -GAMMA2 || (a0 === -GAMMA2 && a1 !== 0))
        return 1;

    return 0;
}

export function useHint(a, hint) {
    let a0 = new Int32Array(1);
    let a1 = decompose(a0, 0, a);

    if(hint === 0)
        return a1;

    if(a0[0] > 0)
        return (a1 + 1) & 15;
    else
        return (a1 - 1) & 15;
}
