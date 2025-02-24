import { SecRunner } from '@sectester/runner';
import { Severity, TestType, AttackParamLocation, HttpMethod } from '@sectester/scan';

jest.setTimeout(15 * 60 * 1000); // 15 minutes

let runner!: SecRunner;

beforeEach(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME!
  });

  await runner.init();
});

afterEach(() => runner.clear());

it('GET /api/nestedJson', async () => {
  await runner
    .createScan({
      name: expect.getState().currentTestName,
      tests: [TestType.EXCESSIVE_DATA_EXPOSURE, TestType.INSECURE_OUTPUT_HANDLING, TestType.FULL_PATH_DISCLOSURE],
      attackParamLocations: [AttackParamLocation.QUERY]
    })
    .threshold(Severity.LOW)
    .timeout(15 * 60 * 1000)
    .run({
      method: HttpMethod.GET,
      url: `${process.env.BRIGHT_TARGET_URL}/api/nestedJson`,
      query: { depth: '1' },
      headers: { 'Content-Type': 'application/json' }
    });
});