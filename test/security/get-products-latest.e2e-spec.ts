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

it('GET /api/products/latest', async () => {
  await runner
    .createScan({
      name: expect.getState().currentTestName,
      tests: [TestType.EXCESSIVE_DATA_EXPOSURE, TestType.SQL_INJECTION],
      attackParamLocations: [AttackParamLocation.QUERY]
    })
    .threshold(Severity.LOW)
    .timeout(20 * 60 * 1000)
    .run({
      method: HttpMethod.GET,
      url: `${process.env.BRIGHT_TARGET_URL}/api/products/latest`,
      query: { limit: '3' }
    });
});