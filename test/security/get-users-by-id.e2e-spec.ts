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
// Testing the GET /api/users/id/1 endpoint

describe('/api/users/id/:id', () => {
  it('should perform a security test on GET /api/users/id/1', async () => {
    await runner
      .createScan({
        tests: [TestType.SQL_INJECTION, TestType.EXCESSIVE_DATA_EXPOSURE, TestType.ID_ENUMERATION, TestType.FULL_PATH_DISCLOSURE],
        name: expect.getState().currentTestName,
        attackParamLocations: [AttackParamLocation.PATH],
        skipStaticParams: false
      })
      .threshold(Severity.LOW)
      .timeout(timeout)
      .run({
        method: HttpMethod.GET,
        url: `${process.env.BRIGHT_TARGET_URL}/api/users/id/1`,
        query: { id: '1' }
      });
  });

  // Additional test cases can be added here
});

// Note: Ensure that the `BRIGHT_HOSTNAME` and `BRIGHT_TARGET_URL` environment variables are set correctly before running the tests.