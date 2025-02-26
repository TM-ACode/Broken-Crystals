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
// Testing the /api/email/sendSupportEmail endpoint

describe('/api/email/sendSupportEmail', () => {
  it('should perform a security test for email injection and data exposure', async () => {
    await runner
      .createScan({
        tests: [TestType.EMAIL_INJECTION, TestType.EXCESSIVE_DATA_EXPOSURE],
        name: expect.getState().currentTestName,
        attackParamLocations: [AttackParamLocation.QUERY],
        skipStaticParams: false
      })
      .threshold(Severity.LOW)
      .timeout(timeout)
      .run({
        method: HttpMethod.GET,
        url: `${process.env.BRIGHT_TARGET_URL}/api/email/sendSupportEmail`,
        headers: {
          'Content-Type': 'application/json'
        },
        query: {
          name: 'Bob Dylan',
          to: 'username@email.com',
          subject: 'Help Request',
          content: 'I would like to request help regarding..'
        }
      });
  });

  // Additional test cases can be added here
});

// Note: Ensure that the `BRIGHT_HOSTNAME` and `BRIGHT_TARGET_URL` environment variables are set correctly before running the tests.