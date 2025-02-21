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

it('DELETE /api/email/deleteEmails', async () => {
  await runner
    .createScan({
      name: expect.getState().currentTestName,
      tests: [TestType.RESOURCE_DELETION, TestType.CROSS_SITE_REQUEST_FORGERY],
      attackParamLocations: [AttackParamLocation.BODY, AttackParamLocation.HEADER],
      skipStaticParams: false
    })
    .threshold(Severity.LOW)
    .timeout(15 * 60 * 1000)
    .run({
      method: HttpMethod.DELETE,
      url: `${process.env.BRIGHT_TARGET_URL}/api/email/deleteEmails`
    });
});
