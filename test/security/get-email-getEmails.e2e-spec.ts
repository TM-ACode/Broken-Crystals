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

it('GET /api/email/getEmails', async () => {
  await runner
    .createScan({
      name: expect.getState().currentTestName,
      tests: [
        TestType.INFORMATION_DISCLOSURE,
        TestType.SQL_INJECTION,
        TestType.CROSS_SITE_SCRIPTING,
        TestType.OS_COMMAND_INJECTION,
        TestType.LOCAL_FILE_INCLUSION,
        TestType.HTTP_RESPONSE_SPLITTING
      ],
      attackParamLocations: [AttackParamLocation.QUERY]
    })
    .threshold(Severity.LOW)
    .timeout(15 * 60 * 1000)
    .run({
      method: HttpMethod.GET,
      url: `${process.env.BRIGHT_TARGET_URL}/api/email/getEmails`,
      query: { withSource: 'true' }
    });
});
