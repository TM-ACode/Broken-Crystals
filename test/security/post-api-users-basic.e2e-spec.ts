import { Severity, AttackParamLocation, HttpMethod } from '@sectester/scan';
import { SecRunner } from '@sectester/runner';

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

it('POST /api/users/basic', async () => {
  await runner
    .createScan({
      tests: ['csrf', 'mass_assignment', 'email_injection', 'excessive_data_exposure', 'stored_xss'],
      attackParamLocations: [AttackParamLocation.BODY]
    })
    .threshold(Severity.CRITICAL)
    .timeout(40 * 60 * 1000)
    .run({
      method: HttpMethod.POST,
      url: `${process.env.BRIGHT_TARGET_URL}/api/users/basic`,
      body: {
        email: 'new.user@example.com',
        firstName: 'New',
        lastName: 'User',
        password: 'securePassword',
        op: 'BASIC'
      }
    });
});
