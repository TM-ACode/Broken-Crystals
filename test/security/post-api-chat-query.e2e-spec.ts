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
// Testing the POST /api/chat/query endpoint

describe('/api/chat/query', () => {
  it('should perform a security test on POST /api/chat/query', async () => {
    await runner
      .createScan({
        tests: [
          TestType.CROSS_SITE_SCRIPTING,
          TestType.SQL_INJECTION,
          TestType.EXCESSIVE_DATA_EXPOSURE,
          TestType.INSECURE_OUTPUT_HANDLING,
          TestType.SERVER_SIDE_REQUEST_FORGERY,
          TestType.PROMPT_INJECTION,
          TestType.EXPOSED_DATABASE_DETAILS
        ],
        name: expect.getState().currentTestName,
        attackParamLocations: [AttackParamLocation.BODY],
        skipStaticParams: false
      })
      .threshold(Severity.LOW)
      .timeout(timeout)
      .run({
        method: HttpMethod.POST,
        url: `${process.env.BRIGHT_TARGET_URL}/api/chat/query`,
        body: [{ "role": "user", "content": "Hello, how are you?" }],
        headers: { 'Content-Type': 'application/json' }
      });
  });

  // Additional test cases can be added here
});

// Note: Ensure that the `BRIGHT_HOSTNAME` and `BRIGHT_TARGET_URL` environment variables are set correctly before running the tests.