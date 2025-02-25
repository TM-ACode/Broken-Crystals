import { SecRunner } from '@sectester/runner';
import { Severity, TestType, AttackParamLocation, HttpMethod } from '@sectester/scan';

jest.setTimeout(20 * 60 * 1000); // 20 minutes

let runner!: SecRunner;

beforeEach(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME!
  });

  await runner.init();
});

afterEach(() => runner.clear());

it('GET /api/partners/partnerLogin', async () => {
  await runner
    .createScan({
      name: expect.getState().currentTestName,
      tests: [TestType.BRUTE_FORCE_LOGIN, TestType.EXCESSIVE_DATA_EXPOSURE, TestType.XPATH_INJECTION],
      attackParamLocations: [AttackParamLocation.QUERY]
    })
    .threshold(Severity.LOW)
    .timeout(20 * 60 * 1000)
    .run({
      method: HttpMethod.GET,
      url: `${process.env.BRIGHT_TARGET_URL}/api/partners/partnerLogin`,
      headers: { 'content-type': 'text/xml' },
      query: { username: 'walter100', password: 'Heisenberg123' }
    });
});