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
// Testing DELETE /api/email/deleteEmails endpoint

describe('/api/email/deleteEmails', () => {
  it('should perform a security test for DELETE /api/email/deleteEmails', async () => {
    await runner
      .createScan({
        tests: [
          TestType.EXCESSIVE_DATA_EXPOSURE,
          TestType.IMPROPER_ASSET_MANAGEMENT,
          TestType.HTTP_METHOD_FUZZING
        ],
        name: expect.getState().currentTestName,
        attackParamLocations: [AttackParamLocation.BODY],
        threshold: Severity.LOW
      })
      .timeout(timeout)
      .run({
        method: HttpMethod.DELETE,
        url: `${process.env.BRIGHT_TARGET_URL}/api/email/deleteEmails`,
        // Add headers, body, or query parameters as needed
      });
  });

  // Additional test cases can be added here
});

// Note: Ensure that the `BRIGHT_HOSTNAME` and `BRIGHT_TARGET_URL` environment variables are set correctly before running the tests.
