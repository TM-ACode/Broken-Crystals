import { SecRunner } from '@sectester/runner';
import { TestType, Severity, HttpMethod, AttackParamLocation } from '@sectester/scan';

jest.setTimeout(15 * 60 * 1000); // 15 minutes

let runner!: SecRunner;

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
      tests: [TestType.XPATH_INJECTION],
      attackParamLocations: [AttackParamLocation.QUERY]
    })
    .threshold(Severity.LOW)
    .timeout(15 * 60 * 1000)
    .run({
      method: HttpMethod.GET,
      url: `${process.env.BRIGHT_TARGET_URL}/api/partners/searchPartners`,
      headers: { 'content-type': 'text/xml' },
      query: { keyword: 'Walter' }
    });
});
