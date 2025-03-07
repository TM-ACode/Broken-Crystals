import { SecRunner } from '@sectester/runner';
import { Severity, AttackParamLocation, HttpMethod } from '@sectester/scan';

jest.setTimeout(40 * 60 * 1000); // 40 minutes

let runner!: SecRunner;

beforeEach(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME!,
    projectId: process.env.BRIGHT_PROJECT_ID!
  });

  await runner.init();
});

afterEach(() => runner.clear());

it('GET /api/email/sendSupportEmail', async () => {
  await runner
    .createScan({
      tests: ['sqli', 'xss', 'date_manipulation'],
      attackParamLocations: [AttackParamLocation.QUERY],
      skipStaticParams: false // Only for date_manipulation
    })
    .threshold(Severity.CRITICAL)
    .timeout(40 * 60 * 1000)
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
