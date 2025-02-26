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
// Testing the /api/partners/query endpoint

describe('/api/partners/query', () => {
  it('should perform a security test for XPATH_INJECTION and XML_EXTERNAL_ENTITY_INJECTION', async () => {
    await runner
      .createScan({
        tests: [TestType.XPATH_INJECTION, TestType.XML_EXTERNAL_ENTITY_INJECTION],
        name: 'GET /api/partners/query - Security Test',
        attackParamLocations: [AttackParamLocation.QUERY],
        skipStaticParams: false
      })
      .threshold(Severity.LOW)
      .timeout(timeout)
      .run({
        method: HttpMethod.GET,
        url: `${process.env.BRIGHT_TARGET_URL}/api/partners/query`,
        headers: { 'content-type': 'text/xml' },
        query: { xpath: '/partners/partner/name' }
      });
  });

  // Additional test cases can be added here
});

// Note: Ensure that the `BRIGHT_HOSTNAME` and `BRIGHT_TARGET_URL` environment variables are set correctly before running the tests.