import { SecRunner } from '@sectester/runner';
import { Severity, TestType, AttackParamLocation, HttpMethod } from '@sectester/scan';

jest.setTimeout(25 * 60 * 1000); // 25 minutes

let runner: SecRunner;

beforeEach(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME!
  });

  await runner.init();
});

afterEach(() => runner.clear());

describe('GET /api/partners/searchPartners', () => {
  it('should test for security vulnerabilities', async () => {
    await runner
      .createScan({
        name: expect.getState().currentTestName,
        tests: [TestType.XPATH_INJECTION, TestType.EXCESSIVE_DATA_EXPOSURE, TestType.INSECURE_OUTPUT_HANDLING],
        attackParamLocations: [AttackParamLocation.QUERY, AttackParamLocation.HEADER]
      })
      .threshold(Severity.LOW)
      .timeout(25 * 60 * 1000)
      .run({
        method: HttpMethod.GET,
        url: `${process.env.BRIGHT_TARGET_URL}/api/partners/searchPartners`,
        headers: { 'content-type': 'text/xml' },
        query: { keyword: 'Walter' }
      });
  });
});
