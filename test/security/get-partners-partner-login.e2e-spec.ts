import { SecRunner } from '@sectester/runner';
import { TestType, Severity, AttackParamLocation, HttpMethod } from '@sectester/scan';

const baseUrl = process.env.BRIGHT_TARGET_URL;

jest.setTimeout(25 * 60 * 1000);

describe('/api', () => {
  const timeout = 25 * 60 * 1000;

  let runner: SecRunner;

  beforeEach(async () => {
    runner = new SecRunner({ hostname: process.env.BRIGHT_CLUSTER });
    await runner.init();
  });

  afterEach(() => runner.clear());

  describe('GET /partners/partnerLogin', () => {
    it('should pass security tests', async () => {
      await runner
        .createScan({
          name: expect.getState().currentTestName,
          tests: [TestType.BRUTE_FORCE_LOGIN, TestType.EXCESSIVE_DATA_EXPOSURE, TestType.XPATH_INJECTION],
          attackParamLocations: [AttackParamLocation.QUERY, AttackParamLocation.HEADER]
        })
        .threshold(Severity.LOW)
        .timeout(timeout)
        .run({
          method: HttpMethod.GET,
          url: `${baseUrl}/api/partners/partnerLogin`,
          headers: { 'content-type': 'text/xml' },
          query: { username: 'walter100', password: 'Heisenberg123' }
        });
    });
  });
});
