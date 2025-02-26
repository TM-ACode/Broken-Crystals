import { SecRunner } from '@sectester/runner';
import { TestType, Severity, AttackParamLocation, HttpMethod } from '@sectester/scan';

// Set a global timeout for all tests
const timeout = 40 * 60 * 1000; // 40 minutes
jest.setTimeout(timeout);

let runner: SecRunner;

beforeEach(async () => {
  // Initialize the SecRunner with the hostname from environment variables
  runner = new SecRunner({ hostname: process.env.BRIGHT_HOSTNAME! });
  await runner.init();
});

afterEach(() => runner.clear());

// Describe the test suite
// Testing the PUT /api/file/raw endpoint

describe('PUT /api/file/raw', () => {
  it('should perform a security test for file upload vulnerabilities', async () => {
    await runner
      .createScan({
        tests: [TestType.FILE_UPLOAD, TestType.EXCESSIVE_DATA_EXPOSURE],
        name: expect.getState().currentTestName,
        attackParamLocations: [AttackParamLocation.BODY, AttackParamLocation.QUERY],
        skipStaticParams: false
      })
      .threshold(Severity.LOW)
      .timeout(timeout)
      .run({
        method: HttpMethod.PUT,
        url: `${process.env.BRIGHT_TARGET_URL}/api/file/raw`,
        query: { path: 'some/path/to/file.png' },
        body: '<file content>',
        headers: { 'Content-Type': 'text/plain' }
      });
  });

  // Additional test cases can be added here
});

// Note: Ensure that the `BRIGHT_HOSTNAME` and `BRIGHT_TARGET_URL` environment variables are set correctly before running the tests.