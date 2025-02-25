import { SecRunner } from '@sectester/runner';
import { TestType, Severity, AttackParamLocation, HttpMethod } from '@sectester/scan';
import axios from 'axios';

describe('/api', () => {
  const timeout = 1500000;
  jest.setTimeout(timeout);

  let runner: SecRunner;

  beforeEach(async () => {
    runner = new SecRunner({ hostname: process.env.BRIGHT_CLUSTER });
    await runner.init();
  });

  afterEach(() => runner.clear());

  describe('GET /partners/searchPartners', () => {
    it('should pass security tests for XPATH_INJECTION and EXCESSIVE_DATA_EXPOSURE', async () => {
      await runner
        .createScan({
          name: expect.getState().currentTestName,
          tests: [TestType.XPATH_INJECTION, TestType.EXCESSIVE_DATA_EXPOSURE],
          attackParamLocations: [AttackParamLocation.QUERY, AttackParamLocation.HEADER]
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