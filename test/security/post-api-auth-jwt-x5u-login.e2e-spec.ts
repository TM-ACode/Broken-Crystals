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
// Testing the JWT login endpoint

describe('/api/auth/jwt/x5u/login', () => {
  it('should perform a security test on JWT login', async () => {
    await runner
      .createScan({
        tests: [
          TestType.BROKEN_JWT_AUTHENTICATION,
          TestType.CROSS_SITE_REQUEST_FORGERY,
          TestType.EXCESSIVE_DATA_EXPOSURE,
          TestType.INSECURE_OUTPUT_HANDLING,
          TestType.SECRET_TOKENS_LEAK
        ],
        name: expect.getState().currentTestName,
        attackParamLocations: [AttackParamLocation.BODY],
        skipStaticParams: false
      })
      .threshold(Severity.LOW)
      .timeout(timeout)
      .run({
        method: HttpMethod.POST,
        url: `${process.env.BRIGHT_TARGET_URL}/api/auth/jwt/x5u/login`,
        body: {
          user: 'example@example.com',
          password: 'password123'
        },
        headers: {
          'Content-Type': 'application/json'
        }
      });
  });

  // Additional test cases can be added here
});

// Note: Ensure that the `BRIGHT_HOSTNAME` and `BRIGHT_TARGET_URL` environment variables are set correctly before running the tests.