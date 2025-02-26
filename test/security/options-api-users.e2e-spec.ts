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
// Testing the OPTIONS method for the /api/users endpoint

describe('/api/users OPTIONS', () => {
  it('should perform a security test for OPTIONS method', async () => {
    await runner
      .createScan({
        tests: [
          TestType.HTTP_METHOD_FUZZING,
          TestType.EXCESSIVE_DATA_EXPOSURE,
          TestType.CROSS_SITE_REQUEST_FORGERY,
          TestType.FULL_PATH_DISCLOSURE
        ],
        name: expect.getState().currentTestName,
        attackParamLocations: [AttackParamLocation.HEADER],
        threshold: Severity.LOW,
        skipStaticParams: false
      })
      .timeout(timeout)
      .run({
        method: HttpMethod.OPTIONS,
        url: `${process.env.BRIGHT_TARGET_URL}/api/users`,
        headers: {
          'Access-Control-Request-Headers': 'OPTIONS, GET, POST, DELETE'
        }
      });
  });

  // Additional test cases can be added here
});

// Note: Ensure that the `BRIGHT_HOSTNAME` and `BRIGHT_TARGET_URL` environment variables are set correctly before running the tests.
