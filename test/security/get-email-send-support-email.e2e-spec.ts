import { SecRunner } from '@sectester/runner';
import { TestType, Severity, AttackParamLocation, HttpMethod } from '@sectester/scan';

jest.setTimeout(15 * 60 * 1000); // 15 minutes

let runner!: SecRunner;

beforeEach(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME!
  });

  await runner.init();
});

afterEach(() => runner.clear());

it('GET /email/sendSupportEmail', async () => {
  await runner
    .createScan({
      name: expect.getState().currentTestName,
      tests: [
        TestType.EMAIL_INJECTION,
        TestType.CROSS_SITE_SCRIPTING,
        TestType.EXCESSIVE_DATA_EXPOSURE,
        TestType.UNVALIDATED_REDIRECT
      ],
      attackParamLocations: [
        AttackParamLocation.QUERY,
        AttackParamLocation.HEADER
      ]
    })
    .threshold(Severity.LOW)
    .timeout(15 * 60 * 1000)
    .run({
      method: HttpMethod.GET,
      url: `${process.env.BRIGHT_TARGET_URL}/api/email/sendSupportEmail`,
      headers: { 'Content-Type': 'application/json' },
      query: {
        name: 'Bob Dylan',
        to: 'username@email.com',
        subject: 'Help Request',
        content: 'I would like to request help regarding..'
      }
    });
});
