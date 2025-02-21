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

it('GET /email/getEmails', async () => {
  await runner
    .createScan({
      name: expect.getState().currentTestName,
      tests: [TestType.SQL_INJECTION, TestType.INFORMATION_DISCLOSURE, TestType.JS_PROTOTYPE_POLLUTION, TestType.UNVALIDATED_REDIRECT, TestType.CROSS_SITE_SCRIPTING],
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
