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
// Testing the /api/auth/dom-csrf-flow endpoint

describe('/api/auth/dom-csrf-flow', () => {
  it('should perform a security test for CSRF and Cookie Security', async () => {
    await runner
      .createScan({
        tests: [TestType.CROSS_SITE_REQUEST_FORGERY, TestType.COOKIE_SECURITY],
        name: expect.getState().currentTestName,
        attackParamLocations: [AttackParamLocation.HEADER],
        skipStaticParams: false
      })
      .threshold(Severity.LOW)
      .timeout(timeout)
      .run({
        method: HttpMethod.GET,
        url: `${process.env.BRIGHT_TARGET_URL}/api/auth/dom-csrf-flow`,
        // Add headers, body, or query parameters as needed
      });
  });

  // Additional test cases can be added here
});

// Note: Ensure that the `BRIGHT_HOSTNAME` and `BRIGHT_TARGET_URL` environment variables are set correctly before running the tests.