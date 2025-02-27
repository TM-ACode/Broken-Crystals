import { Severity, TestType, AttackParamLocation, HttpMethod } from '@sectester/scan';
import { SecRunner } from '@sectester/runner';

jest.setTimeout(40 * 60 * 1000); // 40 minutes

let runner: SecRunner;

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
        TestType.XPATH_INJECTION,
        TestType.EXCESSIVE_DATA_EXPOSURE,
        TestType.INSECURE_OUTPUT_HANDLING
      ],
      attackParamLocations: [AttackParamLocation.QUERY]
    })
    .threshold(Severity.LOW)
    .timeout(40 * 60 * 1000)
    .run({
      method: HttpMethod.GET,
      url: `${process.env.BRIGHT_TARGET_URL}/api/partners/searchPartners`,
      headers: { 'content-type': 'text/xml' },
      query: { keyword: 'Walter' }
    });
});
