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
// Testing the /api/metadata endpoint

describe('/api/metadata', () => {
  it('should perform a security test for XML External Entity Injection', async () => {
    await runner
      .createScan({
        tests: [TestType.XML_EXTERNAL_ENTITY_INJECTION, TestType.EXCESSIVE_DATA_EXPOSURE, TestType.INSECURE_OUTPUT_HANDLING],
        name: expect.getState().currentTestName,
        attackParamLocations: [AttackParamLocation.BODY],
        skipStaticParams: false
      })
      .threshold(Severity.LOW)
      .timeout(timeout)
      .run({
        method: HttpMethod.POST,
        url: `${process.env.BRIGHT_TARGET_URL}/api/metadata`,
        headers: {
          'Content-Type': 'text/xml'
        },
        body: `\u003csvg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 915 585"\u003e\u003cg stroke-width="3.45" fill="none"\u003e\u003cpath stroke="#000" d="M11.8 11.8h411v411l-411 .01v-411z"/\u003e\u003cpath stroke="#448" d="M489 11.7h415v411H489v-411z"/\u003e\u003c/g\u003e\u003c/svg\u003e`
      });
  });

  // Additional test cases can be added here
});

// Note: Ensure that the `BRIGHT_HOSTNAME` and `BRIGHT_TARGET_URL` environment variables are set correctly before running the tests.
