#!/usr/bin/env node

import { Command } from 'commander';
import { scanDirectory, formatResults } from './scanner.js';
import { scanGitHistory, formatGitResults } from './detectors/git.js';
import { scanContainerImage, formatContainerResults } from './detectors/container.js';

const program = new Command();

program
  .name('tailsec-scan-secrets')
  .description('Scan code, repositories, and containers for secrets, API keys, and tokens')
  .version('0.1.0');

program
  .command('scan')
  .description('Scan a directory for secrets')
  .argument('<path>', 'Path to scan')
  .option('-v, --verify', 'Verify found secrets via API calls', false)
  .option('-f, --format <format>', 'Output format (text|json|sarif)', 'text')
  .option('-o, --output <file>', 'Write output to file')
  .option('--git', 'Also scan git history for removed secrets', false)
  .option('--max-commits <n>', 'Maximum number of commits to scan in git history', '1000')
  .action(async (path, options) => {
    try {
      const summary = await scanDirectory(path, {
        verify: options.verify,
        outputFormat: options.format,
      });

      let output = formatResults(summary, options.format);

      if (options.git) {
        const gitResults = await scanGitHistory(path, {
          verify: options.verify,
          maxCommits: parseInt(options.maxCommits, 10),
        });
        const gitOutput = formatGitResults(gitResults);
        output += '\n\n' + gitOutput;
        summary.secretsFound += gitResults.length;
      }

      if (options.output) {
        const { writeFileSync } = await import('fs');
        writeFileSync(options.output, output);
        console.log(`Results written to ${options.output}`);
      } else {
        console.log(output);
      }

      if (summary.secretsFound > 0) {
        process.exit(1);
      }
    } catch (err) {
      console.error(`Error: ${err}`);
      process.exit(1);
    }
  });

program
  .command('git')
  .description('Scan git history for removed secrets')
  .argument('<path>', 'Path to git repository')
  .option('-v, --verify', 'Verify found secrets', false)
  .option('-f, --format <format>', 'Output format (text|json)', 'text')
  .option('-m, --max-commits <n>', 'Maximum commits to scan', '1000')
  .action(async (path, options) => {
    try {
      const results = await scanGitHistory(path, {
        verify: options.verify,
        maxCommits: parseInt(options.maxCommits, 10),
      });

      const output = formatGitResults(results);
      console.log(output);

      if (results.length > 0) {
        process.exit(1);
      }
    } catch (err) {
      console.error(`Error: ${err}`);
      process.exit(1);
    }
  });

program
  .command('container')
  .description('Scan a Docker image for embedded secrets')
  .argument('<image>', 'Docker image name')
  .option('-v, --verify', 'Verify found secrets', false)
  .option('-f, --format <format>', 'Output format (text|json)', 'text')
  .action(async (image, options) => {
    try {
      const result = await scanContainerImage(image, { verify: options.verify });

      const output = formatContainerResults(result);
      console.log(output);

      if (result.secrets.length > 0) {
        process.exit(1);
      }
    } catch (err) {
      console.error(`Error scanning container: ${err}`);
      process.exit(1);
    }
  });

program.parse();