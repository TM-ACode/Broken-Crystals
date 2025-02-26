import { SecRunner } from '@sectester/runner';
import { TestType, Severity, AttackParamLocation, HttpMethod } from '@sectester/scan';

jest.setTimeout(40 * 60 * 1000); // 40 minutes

let runner: SecRunner;

beforeEach(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME!
  });

  await runner.init();
});

afterEach(() => runner.clear());

// Test cases will be added here

describe('Security Tests', () => {
  it('GET /api/partners/partnerLogin', async () => {
    await runner
      .createScan({
        name: expect.getState().currentTestName,
        tests: [
          TestType.XPATH_INJECTION,
          TestType.EXCESSIVE_DATA_EXPOSURE,
          TestType.INSECURE_OUTPUT_HANDLING
        ],
        attackParamLocations: [AttackParamLocation.QUERY],
        skipStaticParams: false
      })
      .threshold(Severity.LOW)
      .timeout(40 * 60 * 1000)
      .run({
        method: HttpMethod.GET,
        url: `${process.env.BRIGHT_TARGET_URL}/api/partners/partnerLogin`,
        headers: {
          'content-type': 'text/xml'
        },
        query: {
          username: 'walter100',
          password: 'Heisenberg123'
        }
      });
  });

  // Additional test cases can be added here
});
