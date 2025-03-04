import { SecRunner } from '@sectester/runner';
import { Severity, TestType, AttackParamLocation, HttpMethod } from '@sectester/scan';

jest.setTimeout(40 * 60 * 1000); // 40 minutes

let runner: SecRunner;

beforeEach(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME!,
    projectId: process.env.BRIGHT_PROJECT_ID!
  });

  await runner.init();
});

afterEach(() => runner.clear());

it('GET /api/partners/query', async () => {
  await runner
    .createScan({
      tests: [
        TestType.XPATH_INJECTION,
        TestType.EXCESSIVE_DATA_EXPOSURE,
        TestType.XML_EXTERNAL_ENTITY_INJECTION
      ],
      attackParamLocations: [AttackParamLocation.QUERY]
    })
    .threshold(Severity.LOW)
    .timeout(40 * 60 * 1000)
    .run({
      method: HttpMethod.GET,
      url: `${process.env.BRIGHT_TARGET_URL}/api/partners/query`,
      headers: { 'content-type': 'text/xml' },
      query: { xpath: '/partners/partner/name' }
    });
});
