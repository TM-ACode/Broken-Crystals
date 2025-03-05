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

it('OPTIONS /api', async () => {
  await runner
    .createScan({
      tests: [
        TestType.INFORMATION_DISCLOSURE,
        TestType.CORS_MISCONFIGURATION,
        TestType.HTTP_METHOD_FUZZING,
        TestType.SECURE_HEADERS,
        TestType.RATE_LIMITING
      ],
      attackParamLocations: [AttackParamLocation.HEADER]
    })
    .threshold(Severity.LOW)
    .timeout(40 * 60 * 1000)
    .run({
      method: HttpMethod.OPTIONS,
      url: `${process.env.BRIGHT_TARGET_URL}/api`,
      headers: {
        allow: 'OPTIONS, GET, HEAD, POST'
      }
    });
});
