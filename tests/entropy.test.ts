/**
 * @license MIT
 * Copyright (c) 2024 Tailsec
 */

import { shannonEntropy } from '../src/lib/entropy.js';

describe('Shannon Entropy', () => {
  test('high entropy for random strings', () => {
    const highEntropy = shannonEntropy('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789');
    expect(highEntropy).toBeGreaterThan(4.5);
  });

  test('low entropy for repeated characters', () => {
    const lowEntropy = shannonEntropy('AAAAAAAAAAAAAAAA');
    expect(lowEntropy).toBeLessThan(2.0);
  });

  test('medium entropy for common words', () => {
    const mediumEntropy = shannonEntropy('password');
    expect(mediumEntropy).toBeGreaterThan(2.5);
    expect(mediumEntropy).toBeLessThan(4.5);
  });

  test('very low entropy for single character', () => {
    const singleChar = shannonEntropy('a');
    expect(singleChar).toBeLessThan(1.0);
  });

  test('AWS access key has reasonable entropy', () => {
    const awsKey = shannonEntropy('AKIAIOSFODNN7EXAMPLE');
    expect(awsKey).toBeGreaterThan(3.0);
  });

  test('GitHub token has high entropy', () => {
    const ghToken = shannonEntropy('ghp_xK4P5L8mN2oP3qR4sT6uV8wX0yZ1aB3cD5e');
    expect(ghToken).toBeGreaterThan(4.5);
  });
});