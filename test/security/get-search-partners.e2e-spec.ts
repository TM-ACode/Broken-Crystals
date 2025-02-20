import { SecRunner } from '@sectester/runner';
import { Severity, TestType, AttackParamLocation, HttpMethod } from '@sectester/scan';

jest.setTimeout(15 * 60 * 1000); // 15 minutes

let runner!: SecRunner;
const baseUrl = process.env.BRIGHT_TARGET_URL || 'http://localhost:3000';

beforeEach(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME!
  });

  await runner.init();
});

afterEach(() => runner.clear());

it('GET /api/partners/searchPartners', async () => {
  await runner
    .createScan({
      name: expect.getState().currentTestName,
      tests: [
        TestType.SQL_INJECTION,
        TestType.CROSS_SITE_SCRIPTING,
        TestType.XML_EXTERNAL_ENTITY_INJECTION,
        TestType.EXCESSIVE_DATA_EXPOSURE,
        TestType.EXPOSED_DATABASE_DETAILS
      ],
      attackParamLocations: [AttackParamLocation.QUERY, AttackParamLocation.HEADER]
    })
    .threshold(Severity.LOW)
    .timeout(15 * 60 * 1000)
    .run({
      method: HttpMethod.GET,
      url: `${baseUrl}/api/partners/searchPartners`,
      headers: { 'content-type': 'text/xml' },
      query: { keyword: 'Walter' }
    });
});