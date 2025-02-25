import { SecRunner } from '@sectester/runner';
import { Severity, TestType, AttackParamLocation, HttpMethod } from '@sectester/scan';

jest.setTimeout(25 * 60 * 1000); // 25 minutes

let runner!: SecRunner;

beforeEach(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME!
  });

  await runner.init();
});

afterEach(() => runner.clear());

it('GET /api/partners/query', async () => {
  await runner
    .createScan({
      name: expect.getState().currentTestName,
      tests: [TestType.XPATH_INJECTION, TestType.EXCESSIVE_DATA_EXPOSURE, TestType.INSECURE_OUTPUT_HANDLING, TestType.FULL_PATH_DISCLOSURE],
      attackParamLocations: [AttackParamLocation.QUERY]
    })
    .threshold(Severity.LOW)
    .timeout(25 * 60 * 1000)
    .run({
      method: HttpMethod.GET,
      url: `${process.env.BRIGHT_TARGET_URL}/api/partners/query`,
      headers: { 'content-type': 'text/xml' },
      query: { xpath: '/partners/partner/name' }
    });
});