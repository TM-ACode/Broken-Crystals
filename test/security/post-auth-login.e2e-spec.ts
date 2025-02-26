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
// Testing the login endpoint

describe('/api/auth/login', () => {
  it('should perform a security test on the login endpoint', async () => {
    await runner
      .createScan({
        tests: [
          TestType.CSRF,
          TestType.JWT,
          TestType.EXCESSIVE_DATA_EXPOSURE,
          TestType.SECRET_TOKENS,
          TestType.INSECURE_OUTPUT_HANDLING
        ],
        name: expect.getState().currentTestName,
        attackParamLocations: [AttackParamLocation.BODY],
        threshold: Severity.LOW
      })
      .timeout(timeout)
      .run({
        method: HttpMethod.POST,
        url: `${process.env.BRIGHT_TARGET_URL}/api/auth/login`,
        body: {
          user: "example@example.com",
          password: "password123"
        }
      });
  });

  // Additional test cases can be added here
});

// Note: Ensure that the `BRIGHT_HOSTNAME` and `BRIGHT_TARGET_URL` environment variables are set correctly before running the tests.