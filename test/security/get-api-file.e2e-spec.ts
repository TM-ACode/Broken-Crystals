import { Severity, TestType, AttackParamLocation, HttpMethod } from '@sectester/scan';
import { SecRunner } from '@sectester/runner';

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

it('GET /api/file', async () => {
  await runner
    .createScan({
      tests: [TestType.DATE_MANIPULATION, TestType.CROSS_SITE_SCRIPTING, TestType.BROKEN_JWT_AUTHENTICATION],
      attackParamLocations: [AttackParamLocation.QUERY]
    })
    .threshold(Severity.LOW)
    .timeout(40 * 60 * 1000)
    .run({
      method: HttpMethod.GET,
      url: `${process.env.BRIGHT_TARGET_URL}/api/file`,
      headers: { accept: 'image/jpg' },
      query: {
        path: 'config/products/crystals/amethyst.jpg',
        type: 'image/jpg'
      }
    });
});
