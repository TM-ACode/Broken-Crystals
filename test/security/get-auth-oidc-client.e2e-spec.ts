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
// Testing the OIDC client endpoint

describe('/api/auth/oidc-client', () => {
  it('should perform a security test on OIDC client endpoint', async () => {
    await runner
      .createScan({
        tests: [
          TestType.EXCESSIVE_DATA_EXPOSURE,
          TestType.SECRET_TOKENS_LEAK,
          TestType.BROKEN_JWT_AUTHENTICATION,
          TestType.CROSS_SITE_REQUEST_FORGERY
        ],
        name: expect.getState().currentTestName,
        attackParamLocations: [AttackParamLocation.HEADER, AttackParamLocation.QUERY]
      })
      .threshold(Severity.LOW)
      .timeout(timeout)
      .run({
        method: HttpMethod.GET,
        url: `${process.env.BRIGHT_TARGET_URL}/api/auth/oidc-client`,
        // Add headers, body, or query parameters as needed
      });
  });

  // Additional test cases can be added here
});

// Note: Ensure that the `BRIGHT_HOSTNAME` and `BRIGHT_TARGET_URL` environment variables are set correctly before running the tests.