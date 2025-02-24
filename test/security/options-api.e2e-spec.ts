import { SecRunner } from '@sectester/runner';
import { TestType, Severity, AttackParamLocation, HttpMethod } from '@sectester/scan';

describe('/api', () => {
  const timeout = 600000;
  jest.setTimeout(timeout);

  let runner: SecRunner;

  beforeEach(async () => {
    runner = new SecRunner({ hostname: process.env.BRIGHT_CLUSTER });
    await runner.init();
  });

  afterEach(() => runner.clear());

  describe('OPTIONS /api', () => {
    it('should test for HTTP method fuzzing and excessive data exposure', async () => {
      await runner
        .createScan({
          tests: [TestType.HTTP_METHOD_FUZZING, TestType.EXCESSIVE_DATA_EXPOSURE],
          attackParamLocations: [AttackParamLocation.HEADER],
          name: 'HTTP_METHOD_FUZZING and EXCESSIVE_DATA_EXPOSURE'
        })
        .threshold(Severity.LOW)
        .timeout(timeout)
        .run({
          method: HttpMethod.OPTIONS,
          url: `${process.env.SEC_TESTER_TARGET}/api`,
          headers: { Allow: 'OPTIONS, GET, HEAD, POST' }
        });
    });
  });
});