import { SecRunner } from '@sectester/runner';
import { TestType, Severity, AttackParamLocation, HttpMethod } from '@sectester/scan';
import axios from 'axios';

describe('/api/partners/query', () => {
  const timeout = 1200000; // 20 minutes
  jest.setTimeout(timeout);

  let runner: SecRunner;

  beforeEach(async () => {
    runner = new SecRunner({ hostname: process.env.BRIGHT_CLUSTER });
    await runner.init();
  });

  afterEach(() => runner.clear());

  it('GET /api/partners/query', async () => {
    await runner
      .createScan({
        name: expect.getState().currentTestName,
        tests: [
          TestType.XPATH_INJECTION,
          TestType.EXCESSIVE_DATA_EXPOSURE,
          TestType.FULL_PATH_DISCLOSURE,
          TestType.EXPOSED_DATABASE_DETAILS
        ],
        attackParamLocations: [AttackParamLocation.QUERY, AttackParamLocation.HEADER]
      })
      .threshold(Severity.LOW)
      .timeout(timeout)
      .run({
        method: HttpMethod.GET,
        url: `${process.env.BRIGHT_TARGET_URL}/api/partners/query`,
        headers: { 'content-type': 'text/xml' },
        query: { xpath: '/partners/partner/name' }
      });
  });
});
