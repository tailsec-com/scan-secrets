/**
 * @license MIT
 * Copyright (c) 2024 Tailsec
 */

export function shannonEntropy(str) {
    if (str.length === 0)
        return 0;
    const freq = {};
    for (const char of str) {
        freq[char] = (freq[char] || 0) + 1;
    }
    let entropy = 0;
    const len = str.length;
    for (const count of Object.values(freq)) {
        const p = count / len;
        entropy -= p * Math.log2(p);
    }
    return entropy;
}
export function isHighEntropy(str, threshold = 4.5) {
    return shannonEntropy(str) >= threshold;
}
export function cleanString(str) {
    return str.replace(/[\r\n]+/g, ' ').trim();
}
