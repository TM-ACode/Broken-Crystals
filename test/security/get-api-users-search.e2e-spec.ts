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
// Testing the /api/users/search endpoint

describe('/api/users/search', () => {
  it('should perform a security test for searching users by name', async () => {
    await runner
      .createScan({
        tests: [TestType.SQL_INJECTION, TestType.CROSS_SITE_SCRIPTING],
        name: 'GET /api/users/search by name',
        attackParamLocations: [AttackParamLocation.QUERY],
        threshold: Severity.LOW,
        skipStaticParams: false
      })
      .timeout(timeout)
      .run({
        method: HttpMethod.GET,
        url: `${process.env.BRIGHT_TARGET_URL}/api/users/search`,
        query: { name: 'john' }
      });
  });

  // Additional test cases can be added here
});

// Note: Ensure that the `BRIGHT_HOSTNAME` and `BRIGHT_TARGET_URL` environment variables are set correctly before running the tests.