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
// Testing the POST /api/users/basic endpoint

describe('/api/users/basic', () => {
  it('should perform a security test on POST /api/users/basic', async () => {
    await runner
      .createScan({
        name: expect.getState().currentTestName,
        tests: [TestType.SQL_INJECTION, TestType.CROSS_SITE_SCRIPTING],
        attackParamLocations: [AttackParamLocation.BODY],
        skipStaticParams: false
      })
      .threshold(Severity.LOW)
      .timeout(timeout)
      .run({
        method: HttpMethod.POST,
        url: `${process.env.BRIGHT_TARGET_URL}/api/users/basic`,
        body: {
          email: "john.doe@example.com",
          firstName: "John",
          lastName: "Doe",
          password: "password123",
          op: "BASIC"
        },
        headers: {
          'Content-Type': 'application/json'
        }
      });
  });

  // Additional test cases can be added here
});

// Note: Ensure that the `BRIGHT_HOSTNAME` and `BRIGHT_TARGET_URL` environment variables are set correctly before running the tests.