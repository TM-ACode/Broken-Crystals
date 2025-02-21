import { SecRunner } from '@sectester/runner';
import { TestType, Severity, AttackParamLocation, HttpMethod } from '@sectester/scan';
import axios from 'axios';

describe('/api', () => {
  const timeout = 900000;
  jest.setTimeout(timeout);

  let runner: SecRunner;

  beforeEach(async () => {
    runner = new SecRunner({ hostname: process.env.BRIGHT_CLUSTER });
    await runner.init();
  });

  afterEach(() => runner.clear());

  describe('GET /partners/searchPartners', () => {
    it('should test for XPATH Injection', async () => {
      await runner
        .createScan({
          name: expect.getState().currentTestName,
          tests: [TestType.XPATH_INJECTION],
          attackParamLocations: [AttackParamLocation.QUERY]
        })
        .threshold(Severity.LOW)
        .timeout(timeout)
        .run({
          method: HttpMethod.GET,
          url: `${process.env.SEC_TESTER_TARGET}/api/partners/searchPartners`,
          headers: { 'content-type': 'text/xml' },
          query: { keyword: 'Walter' }
        });
    });
  });
});
