#!/usr/bin/env node
/**
 * Comprehensive test runner for PhishContext AI frontend
 * Runs all test suites with coverage reporting and performance metrics
 */

const { execSync, spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

class FrontendTestRunner {
  constructor() {
    this.projectRoot = __dirname;
    this.testResults = {};
    this.startTime = Date.now();
  }

  runCommand(command, options = {}) {
    const startTime = Date.now();
    console.log(`Running: ${command}`);

    try {
      const result = execSync(command, {
        cwd: this.projectRoot,
        encoding: 'utf8',
        timeout: 300000, // 5 minutes
        ...options
      });

      return {
        success: true,
        output: result,
        duration: Date.now() - startTime
      };
    } catch (error) {
      return {
        success: false,
        output: error.stdout || '',
        error: error.stderr || error.message,
        duration: Date.now() - startTime
      };
    }
  }

  async runAsyncCommand(command, args = []) {
    return new Promise((resolve) => {
      const startTime = Date.now();
      console.log(`Running: ${command} ${args.join(' ')}`);

      const child = spawn(command, args, {
        cwd: this.projectRoot,
        stdio: 'pipe'
      });

      let stdout = '';
      let stderr = '';

      child.stdout.on('data', (data) => {
        stdout += data.toString();
        process.stdout.write(data);
      });

      child.stderr.on('data', (data) => {
        stderr += data.toString();
        process.stderr.write(data);
      });

      child.on('close', (code) => {
        resolve({
          success: code === 0,
          output: stdout,
          error: stderr,
          duration: Date.now() - startTime
        });
      });

      // Timeout after 5 minutes
      setTimeout(() => {
        child.kill();
        resolve({
          success: false,
          output: stdout,
          error: 'Test execution timed out',
          duration: Date.now() - startTime
        });
      }, 300000);
    });
  }

  runUnitTests() {
    console.log('\n' + '='.repeat(50));
    console.log('RUNNING UNIT TESTS');
    console.log('='.repeat(50));

    // Run vitest with coverage
    const result = this.runCommand('npm run test:coverage', {
      stdio: 'inherit'
    });

    // Parse coverage data if available
    let coverageData = null;
    const coverageFile = path.join(this.projectRoot, 'coverage', 'coverage-summary.json');
    if (fs.existsSync(coverageFile)) {
      try {
        coverageData = JSON.parse(fs.readFileSync(coverageFile, 'utf8'));
      } catch (e) {
        console.warn('Warning: Could not parse coverage data:', e.message);
      }
    }

    return {
      ...result,
      coverage: coverageData
    };
  }

  runComponentTests() {
    console.log('\n' + '='.repeat(50));
    console.log('RUNNING COMPONENT TESTS');
    console.log('='.repeat(50));

    // Run component-specific tests
    return this.runCommand('npm run test -- --run src/components/', {
      stdio: 'inherit'
    });
  }

  runIntegrationTests() {
    console.log('\n' + '='.repeat(50));
    console.log('RUNNING INTEGRATION TESTS');
    console.log('='.repeat(50));

    // Run integration tests
    return this.runCommand('npm run test -- --run src/services/', {
      stdio: 'inherit'
    });
  }

  runE2ETests() {
    console.log('\n' + '='.repeat(50));
    console.log('RUNNING END-TO-END TESTS');
    console.log('='.repeat(50));

    // Run e2e tests
    return this.runCommand('npm run test -- --run e2e/', {
      stdio: 'inherit'
    });
  }

  runAccessibilityTests() {
    console.log('\n' + '='.repeat(50));
    console.log('RUNNING ACCESSIBILITY TESTS');
    console.log('='.repeat(50));

    // Run accessibility tests using axe
    return this.runCommand('npm run test:a11y', {
      stdio: 'inherit'
    });
  }

  runPerformanceTests() {
    console.log('\n' + '='.repeat(50));
    console.log('RUNNING PERFORMANCE TESTS');
    console.log('='.repeat(50));

    // Run performance tests
    return this.runCommand('npm run test -- --run e2e/performance-load.test.ts', {
      stdio: 'inherit'
    });
  }

  checkCodeQuality() {
    console.log('\n' + '='.repeat(50));
    console.log('RUNNING CODE QUALITY CHECKS');
    console.log('='.repeat(50));

    const results = {};

    // Run ESLint
    console.log('Running ESLint...');
    results.eslint = this.runCommand('npm run lint');

    // Run TypeScript check
    console.log('Running TypeScript check...');
    results.typescript = this.runCommand('npm run type-check');

    // Run Prettier check
    console.log('Running Prettier check...');
    results.prettier = this.runCommand('npm run format:check');

    return {
      ...results,
      success: Object.values(results).every(r => r.success)
    };
  }

  buildProject() {
    console.log('\n' + '='.repeat(50));
    console.log('BUILDING PROJECT');
    console.log('='.repeat(50));

    return this.runCommand('npm run build', {
      stdio: 'inherit'
    });
  }

  generateReport() {
    const totalDuration = Date.now() - this.startTime;

    console.log('\n' + '='.repeat(70));
    console.log('TEST EXECUTION SUMMARY');
    console.log('='.repeat(70));

    let overallSuccess = true;

    for (const [testType, result] of Object.entries(this.testResults)) {
      const status = result.success ? '✅ PASS' : '❌ FAIL';
      const duration = result.duration || 0;

      console.log(`${testType.padEnd(20)} ${status.padEnd(10)} (${(duration / 1000).toFixed(2)}s)`);

      if (!result.success) {
        overallSuccess = false;
        if (result.error) {
          console.log(`  Error: ${result.error.substring(0, 100)}...`);
        }
      }
    }

    console.log('-'.repeat(70));
    console.log(`Total Duration: ${(totalDuration / 1000).toFixed(2)}s`);
    console.log(`Overall Status: ${overallSuccess ? '✅ ALL TESTS PASSED' : '❌ SOME TESTS FAILED'}`);

    // Coverage summary
    const unitTestResult = this.testResults.unit_tests || {};
    const coverageData = unitTestResult.coverage;
    if (coverageData && coverageData.total) {
      const totalCoverage = coverageData.total.lines.pct;
      console.log(`Code Coverage: ${totalCoverage}%`);
    }

    console.log('='.repeat(70));

    // Generate JSON report
    const reportData = {
      timestamp: Date.now(),
      duration: totalDuration,
      success: overallSuccess,
      results: this.testResults
    };

    fs.writeFileSync('test-report.json', JSON.stringify(reportData, null, 2));
    console.log('Detailed report saved to: test-report.json');

    if (!overallSuccess) {
      process.exit(1);
    }
  }

  async runAllTests() {
    console.log('Starting comprehensive test execution...');
    console.log(`Project root: ${this.projectRoot}`);

    // Install dependencies
    console.log('Installing dependencies...');
    const depsResult = this.runCommand('npm ci');
    if (!depsResult.success) {
      console.error('Failed to install dependencies');
      process.exit(1);
    }

    // Run test suites
    const testSuites = [
      ['unit_tests', () => this.runUnitTests()],
      ['component_tests', () => this.runComponentTests()],
      ['integration_tests', () => this.runIntegrationTests()],
      ['e2e_tests', () => this.runE2ETests()],
      ['accessibility_tests', () => this.runAccessibilityTests()],
      ['performance_tests', () => this.runPerformanceTests()],
      ['code_quality', () => this.checkCodeQuality()],
      ['build', () => this.buildProject()]
    ];

    for (const [testName, testFunc] of testSuites) {
      try {
        console.log(`\nExecuting ${testName}...`);
        this.testResults[testName] = testFunc();
      } catch (error) {
        console.error(`Error running ${testName}:`, error.message);
        this.testResults[testName] = {
          success: false,
          error: error.message,
          duration: 0
        };
      }
    }

    // Generate final report
    this.generateReport();
  }
}

function main() {
  const args = process.argv.slice(2);
  const suite = args.find(arg => arg.startsWith('--suite='))?.split('=')[1] || 'all';
  const verbose = args.includes('--verbose') || args.includes('-v');
  const coverage = args.includes('--coverage');

  if (verbose) {
    console.log('Verbose mode enabled');
  }

  const runner = new FrontendTestRunner();

  switch (suite) {
    case 'all':
      runner.runAllTests();
      break;
    case 'unit':
      runner.testResults.unit_tests = runner.runUnitTests();
      runner.generateReport();
      break;
    case 'component':
      runner.testResults.component_tests = runner.runComponentTests();
      runner.generateReport();
      break;
    case 'integration':
      runner.testResults.integration_tests = runner.runIntegrationTests();
      runner.generateReport();
      break;
    case 'e2e':
      runner.testResults.e2e_tests = runner.runE2ETests();
      runner.generateReport();
      break;
    case 'a11y':
      runner.testResults.accessibility_tests = runner.runAccessibilityTests();
      runner.generateReport();
      break;
    case 'performance':
      runner.testResults.performance_tests = runner.runPerformanceTests();
      runner.generateReport();
      break;
    case 'quality':
      runner.testResults.code_quality = runner.checkCodeQuality();
      runner.generateReport();
      break;
    case 'build':
      runner.testResults.build = runner.buildProject();
      runner.generateReport();
      break;
    default:
      console.error(`Unknown test suite: ${suite}`);
      console.error('Available suites: all, unit, component, integration, e2e, a11y, performance, quality, build');
      process.exit(1);
  }
}

if (require.main === module) {
  main();
}

module.exports = FrontendTestRunner;