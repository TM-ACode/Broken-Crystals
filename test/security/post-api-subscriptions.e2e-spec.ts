import { Severity, TestType, AttackParamLocation, HttpMethod } from '@sectester/scan';
import { SecRunner } from '@sectester/runner';

jest.setTimeout(40 * 60 * 1000); // 40 minutes

let runner!: SecRunner;

beforeEach(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME!
  });

  await runner.init();
});

afterEach(() => runner.clear());

it('POST /api/subscriptions', async () => {
  await runner
    .createScan({
      name: expect.getState().currentTestName,
      tests: [TestType.EMAIL_INJECTION, TestType.EXCESSIVE_DATA_EXPOSURE, TestType.INSECURE_OUTPUT_HANDLING],
      attackParamLocations: [AttackParamLocation.QUERY]
    })
    .threshold(Severity.LOW)
    .timeout(40 * 60 * 1000)
    .run({
      method: HttpMethod.POST,
      url: `${process.env.BRIGHT_TARGET_URL}/api/subscriptions`,
      query: { email: 'john.doe@example.com' }
    });
});
