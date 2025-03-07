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

it('OPTIONS /api/users', async () => {
  await runner
    .createScan({
      tests: ['http_method_fuzzing'],
      attackParamLocations: [AttackParamLocation.HEADER]
    })
    .threshold(Severity.CRITICAL)
    .timeout(40 * 60 * 1000)
    .run({
      method: HttpMethod.OPTIONS,
      url: `${process.env.BRIGHT_TARGET_URL}/api/users`,
      headers: {
        'Access-Control-Request-Headers': 'OPTIONS, GET, POST, DELETE'
      }
    });
});
