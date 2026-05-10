export function shannonEntropy(str: string): number {
  if (str.length === 0) return 0;

  const freq: Record<string, number> = {};
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

export function isHighEntropy(str: string, threshold = 4.5): boolean {
  return shannonEntropy(str) >= threshold;
}

export function cleanString(str: string): string {
  return str.replace(/[\r\n]+/g, ' ').trim();
}