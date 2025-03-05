import { SecRunner } from '@sectester/runner';
import { Severity, TestType, AttackParamLocation, HttpMethod } from '@sectester/scan';

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

it('GET /api/products/latest', async () => {
  await runner
    .createScan({
      tests: [
        TestType.INPUT_VALIDATION,
        TestType.RATE_LIMITING,
        TestType.INFORMATION_DISCLOSURE,
        TestType.SECURE_HEADERS,
        TestType.DATA_VALIDATION
      ],
      attackParamLocations: [AttackParamLocation.QUERY]
    })
    .threshold(Severity.LOW)
    .timeout(40 * 60 * 1000)
    .run({
      method: HttpMethod.GET,
      url: `${process.env.BRIGHT_TARGET_URL}/api/products/latest`,
      query: { limit: '3' }
    });
});
