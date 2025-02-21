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

it('GET /sendSupportEmail', async () => {
  await runner
    .createScan({
      name: expect.getState().currentTestName,
      tests: [TestType.PROTOTYPE_POLLUTION, TestType.SQL_INJECTION, TestType.CROSS_SITE_SCRIPTING, TestType.EMAIL_INJECTION],
      attackParamLocations: [AttackParamLocation.QUERY]
    })
    .threshold(Severity.LOW)
    .timeout(15 * 60 * 1000)
    .run({
      method: HttpMethod.GET,
      url: `${process.env.BRIGHT_TARGET_URL}/api/email/sendSupportEmail`,
      query: {
        name: 'Bob Dylan',
        to: 'username@email.com',
        subject: 'Help Request',
        content: 'I would like to request help regarding..'
      }
    });
});
