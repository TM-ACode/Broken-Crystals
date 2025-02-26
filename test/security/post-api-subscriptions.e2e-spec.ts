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
// Testing the POST /api/subscriptions endpoint

describe('/api/subscriptions', () => {
  it('should perform a security test for POST /api/subscriptions', async () => {
    await runner
      .createScan({
        tests: [
          TestType.EMAIL_INJECTION,
          TestType.EXCESSIVE_DATA_EXPOSURE,
          TestType.INSECURE_OUTPUT_HANDLING,
          TestType.CROSS_SITE_SCRIPTING
        ],
        name: expect.getState().currentTestName,
        attackParamLocations: [AttackParamLocation.QUERY],
        skipStaticParams: false
      })
      .threshold(Severity.LOW)
      .timeout(timeout)
      .run({
        method: HttpMethod.POST,
        url: `${process.env.BRIGHT_TARGET_URL}/api/subscriptions`,
        query: { email: 'john.doe@example.com' }
      });
  });

  // Additional test cases can be added here
});

// Note: Ensure that the `BRIGHT_HOSTNAME` and `BRIGHT_TARGET_URL` environment variables are set correctly before running the tests.