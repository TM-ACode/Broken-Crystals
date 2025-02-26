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
  it('GET /api/partners/query', async () => {
    await runner
      .createScan({
        name: expect.getState().currentTestName,
        tests: [
          TestType.XPATH_INJECTION,
          TestType.EXCESSIVE_DATA_EXPOSURE,
          TestType.XML_EXTERNAL_ENTITY_INJECTION
        ],
        attackParamLocations: [AttackParamLocation.QUERY],
        skipStaticParams: false
      })
      .threshold(Severity.LOW)
      .timeout(40 * 60 * 1000)
      .run({
        method: HttpMethod.GET,
        url: `${process.env.BRIGHT_TARGET_URL}/api/partners/query`,
        headers: {
          'content-type': 'text/xml'
        },
        query: {
          xpath: '/partners/partner/name'
        }
      });
  });

  // Additional test cases can be added here
});
