#!/usr/bin/env python3
"""
Comprehensive test runner for PhishContext AI backend
Runs all test suites with coverage reporting and performance metrics
"""

import os
import sys
import subprocess
import time
import json
from pathlib import Path
from typing import Dict, List, Optional

class TestRunner:
    """Comprehensive test runner with reporting and metrics"""
    
    def __init__(self):
        self.project_root = Path(__file__).parent
        self.test_results = {}
        self.start_time = time.time()
        
    def run_command(self, command: List[str], cwd: Optional[Path] = None) -> Dict:
        """Run a command and capture results"""
        if cwd is None:
            cwd = self.project_root
            
        print(f"Running: {' '.join(command)}")
        start_time = time.time()
        
        try:
            result = subprocess.run(
                command,
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            duration = time.time() - start_time
            
            return {
                'success': result.returncode == 0,
                'returncode': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'duration': duration
            }
            
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'returncode': -1,
                'stdout': '',
                'stderr': 'Test execution timed out',
                'duration': time.time() - start_time
            }
        except Exception as e:
            return {
                'success': False,
                'returncode': -1,
                'stdout': '',
                'stderr': str(e),
                'duration': time.time() - start_time
            }
    
    def run_unit_tests(self) -> Dict:
        """Run unit tests with coverage"""
        print("\n" + "="*50)
        print("RUNNING UNIT TESTS")
        print("="*50)
        
        # Run pytest with coverage
        result = self.run_command([
            'python', '-m', 'pytest',
            'tests/',
            '--cov=app',
            '--cov-report=html:htmlcov',
            '--cov-report=term-missing',
            '--cov-report=json:coverage.json',
            '--junit-xml=test-results.xml',
            '-v',
            '--tb=short'
        ])
        
        # Parse coverage data if available
        coverage_data = None
        coverage_file = self.project_root / 'coverage.json'
        if coverage_file.exists():
            try:
                with open(coverage_file) as f:
                    coverage_data = json.load(f)
            except Exception as e:
                print(f"Warning: Could not parse coverage data: {e}")
        
        return {
            **result,
            'coverage': coverage_data
        }
    
    def run_integration_tests(self) -> Dict:
        """Run integration tests"""
        print("\n" + "="*50)
        print("RUNNING INTEGRATION TESTS")
        print("="*50)
        
        # Run integration tests separately
        result = self.run_command([
            'python', '-m', 'pytest',
            'tests/',
            '-m', 'integration',
            '-v',
            '--tb=short'
        ])
        
        return result
    
    def run_api_tests(self) -> Dict:
        """Run API endpoint tests"""
        print("\n" + "="*50)
        print("RUNNING API TESTS")
        print("="*50)
        
        # Run API-specific tests
        result = self.run_command([
            'python', '-m', 'pytest',
            'tests/test_main.py',
            '-v',
            '--tb=short'
        ])
        
        return result
    
    def run_security_tests(self) -> Dict:
        """Run security-focused tests"""
        print("\n" + "="*50)
        print("RUNNING SECURITY TESTS")
        print("="*50)
        
        # Run security validation
        security_result = self.run_command([
            'python', 'validate_security.py'
        ])
        
        # Run security-focused pytest
        pytest_result = self.run_command([
            'python', '-m', 'pytest',
            'tests/test_security_features.py',
            '-v',
            '--tb=short'
        ])
        
        return {
            'security_validation': security_result,
            'security_tests': pytest_result,
            'success': security_result['success'] and pytest_result['success']
        }
    
    def run_performance_tests(self) -> Dict:
        """Run performance tests"""
        print("\n" + "="*50)
        print("RUNNING PERFORMANCE TESTS")
        print("="*50)
        
        # Run performance-focused tests
        result = self.run_command([
            'python', '-m', 'pytest',
            'tests/',
            '-m', 'performance',
            '-v',
            '--tb=short'
        ])
        
        return result
    
    def check_code_quality(self) -> Dict:
        """Run code quality checks"""
        print("\n" + "="*50)
        print("RUNNING CODE QUALITY CHECKS")
        print("="*50)
        
        results = {}
        
        # Run flake8
        print("Running flake8...")
        results['flake8'] = self.run_command(['flake8', 'app/', 'tests/'])
        
        # Run mypy if available
        print("Running mypy...")
        results['mypy'] = self.run_command(['python', '-m', 'mypy', 'app/'])
        
        # Run bandit for security
        print("Running bandit...")
        results['bandit'] = self.run_command([
            'python', '-m', 'bandit', '-r', 'app/', '-f', 'json', '-o', 'bandit-report.json'
        ])
        
        return {
            **results,
            'success': all(r['success'] for r in results.values())
        }
    
    def generate_report(self) -> None:
        """Generate comprehensive test report"""
        total_duration = time.time() - self.start_time
        
        print("\n" + "="*70)
        print("TEST EXECUTION SUMMARY")
        print("="*70)
        
        overall_success = True
        
        for test_type, result in self.test_results.items():
            status = "✅ PASS" if result['success'] else "❌ FAIL"
            duration = result.get('duration', 0)
            
            print(f"{test_type:<20} {status:<10} ({duration:.2f}s)")
            
            if not result['success']:
                overall_success = False
                if result.get('stderr'):
                    print(f"  Error: {result['stderr'][:100]}...")
        
        print("-" * 70)
        print(f"Total Duration: {total_duration:.2f}s")
        print(f"Overall Status: {'✅ ALL TESTS PASSED' if overall_success else '❌ SOME TESTS FAILED'}")
        
        # Coverage summary
        unit_test_result = self.test_results.get('unit_tests', {})
        coverage_data = unit_test_result.get('coverage')
        if coverage_data:
            total_coverage = coverage_data.get('totals', {}).get('percent_covered', 0)
            print(f"Code Coverage: {total_coverage:.1f}%")
        
        print("="*70)
        
        # Generate JSON report
        report_data = {
            'timestamp': time.time(),
            'duration': total_duration,
            'success': overall_success,
            'results': self.test_results
        }
        
        with open('test-report.json', 'w') as f:
            json.dump(report_data, f, indent=2)
        
        print(f"Detailed report saved to: test-report.json")
        
        if not overall_success:
            sys.exit(1)
    
    def run_all_tests(self) -> None:
        """Run all test suites"""
        print("Starting comprehensive test execution...")
        print(f"Project root: {self.project_root}")
        
        # Check if we're in a virtual environment
        if not os.environ.get('VIRTUAL_ENV'):
            print("Warning: Not running in a virtual environment")
        
        # Install test dependencies
        print("Installing test dependencies...")
        deps_result = self.run_command([
            'pip', 'install', '-e', '.', '--quiet'
        ])
        
        if not deps_result['success']:
            print("Failed to install dependencies")
            sys.exit(1)
        
        # Run test suites
        test_suites = [
            ('unit_tests', self.run_unit_tests),
            ('integration_tests', self.run_integration_tests),
            ('api_tests', self.run_api_tests),
            ('security_tests', self.run_security_tests),
            ('performance_tests', self.run_performance_tests),
            ('code_quality', self.check_code_quality)
        ]
        
        for test_name, test_func in test_suites:
            try:
                print(f"\nExecuting {test_name}...")
                self.test_results[test_name] = test_func()
            except Exception as e:
                print(f"Error running {test_name}: {e}")
                self.test_results[test_name] = {
                    'success': False,
                    'error': str(e),
                    'duration': 0
                }
        
        # Generate final report
        self.generate_report()


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Run PhishContext AI backend tests')
    parser.add_argument('--suite', choices=['unit', 'integration', 'api', 'security', 'performance', 'quality', 'all'], 
                       default='all', help='Test suite to run')
    parser.add_argument('--coverage', action='store_true', help='Generate coverage report')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    runner = TestRunner()
    
    if args.suite == 'all':
        runner.run_all_tests()
    elif args.suite == 'unit':
        result = runner.run_unit_tests()
        runner.test_results['unit_tests'] = result
        runner.generate_report()
    elif args.suite == 'integration':
        result = runner.run_integration_tests()
        runner.test_results['integration_tests'] = result
        runner.generate_report()
    elif args.suite == 'api':
        result = runner.run_api_tests()
        runner.test_results['api_tests'] = result
        runner.generate_report()
    elif args.suite == 'security':
        result = runner.run_security_tests()
        runner.test_results['security_tests'] = result
        runner.generate_report()
    elif args.suite == 'performance':
        result = runner.run_performance_tests()
        runner.test_results['performance_tests'] = result
        runner.generate_report()
    elif args.suite == 'quality':
        result = runner.check_code_quality()
        runner.test_results['code_quality'] = result
        runner.generate_report()


if __name__ == '__main__':
    main()