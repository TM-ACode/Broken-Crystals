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

it('GET /api/auth/simple-csrf-flow', async () => {
  await runner
    .createScan({
      name: expect.getState().currentTestName,
      tests: [TestType.CROSS_SITE_REQUEST_FORGERY, TestType.EXCESSIVE_DATA_EXPOSURE, TestType.SECRET_TOKENS_LEAK],
      attackParamLocations: [AttackParamLocation.QUERY, AttackParamLocation.HEADER]
    })
    .threshold(Severity.LOW)
    .timeout(15 * 60 * 1000)
    .run({
      method: HttpMethod.GET,
      url: `${process.env.BRIGHT_TARGET_URL}/api/auth/simple-csrf-flow`
    });
});
