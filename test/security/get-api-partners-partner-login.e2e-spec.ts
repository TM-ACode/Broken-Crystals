import { SecRunner } from '@sectester/runner';
import { Severity, AttackParamLocation, HttpMethod } from '@sectester/scan';

jest.setTimeout(40 * 60 * 1000); // 40 minutes

let runner: SecRunner;

beforeEach(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME!,
    projectId: process.env.BRIGHT_PROJECT_ID!
  });

  await runner.init();
});

afterEach(() => runner.clear());

it('GET /api/partners/partnerLogin', async () => {
  await runner
    .createScan({
      tests: ['xpathi'],
      attackParamLocations: [AttackParamLocation.QUERY, AttackParamLocation.HEADER]
    })
    .threshold(Severity.CRITICAL)
    .timeout(40 * 60 * 1000)
    .run({
      method: HttpMethod.GET,
      url: `${process.env.BRIGHT_TARGET_URL}/api/partners/partnerLogin`,
      headers: {
        'content-type': 'text/xml'
      },
      query: {
        username: 'walter100',
        password: 'Heisenberg123'
      }
    });
});
