import { SecRunner } from '@sectester/runner';
import { Severity, TestType, AttackParamLocation, HttpMethod } from '@sectester/scan';

jest.setTimeout(40 * 60 * 1000); // 40 minutes

let runner!: SecRunner;

beforeEach(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME!
  });

  await runner.init();
});

afterEach(() => runner.clear());

it('GET /api/spawn', async () => {
  await runner
    .createScan({
      name: expect.getState().currentTestName,
      tests: [TestType.OS_COMMAND_INJECTION, TestType.EXCESSIVE_DATA_EXPOSURE, TestType.INSECURE_OUTPUT_HANDLING],
      attackParamLocations: [AttackParamLocation.QUERY]
    })
    .threshold(Severity.MEDIUM)
    .timeout(40 * 60 * 1000)
    .run({
      method: HttpMethod.GET,
      url: `${process.env.BRIGHT_TARGET_URL}/api/spawn`,
      query: { command: 'ls -la' }
    });
});
