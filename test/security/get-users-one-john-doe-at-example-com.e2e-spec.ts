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
// Testing the endpoint for potential vulnerabilities

describe('/api/users/one/john.doe@example.com', () => {
  it('should perform a security test on GET /api/users/one/john.doe@example.com', async () => {
    await runner
      .createScan({
        name: expect.getState().currentTestName,
        tests: [
          TestType.EMAIL_INJECTION,
          TestType.EXCESSIVE_DATA_EXPOSURE,
          TestType.LDAP_INJECTION,
          TestType.EXPOSED_DATABASE_DETAILS
        ],
        attackParamLocations: [AttackParamLocation.QUERY],
        skipStaticParams: false
      })
      .threshold(Severity.LOW)
      .timeout(timeout)
      .run({
        method: HttpMethod.GET,
        url: `${process.env.BRIGHT_TARGET_URL}/api/users/one/john.doe@example.com`,
        query: { email: 'john.doe@example.com' }
      });
  });

  // Additional test cases can be added here
});

// Note: Ensure that the `BRIGHT_HOSTNAME` and `BRIGHT_TARGET_URL` environment variables are set correctly before running the tests.