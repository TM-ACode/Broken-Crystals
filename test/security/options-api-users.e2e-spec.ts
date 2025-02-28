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

it('OPTIONS /api/users', async () => {
  await runner
    .createScan({
      tests: [
        TestType.HTTP_METHOD_FUZZING,
        TestType.EXCESSIVE_DATA_EXPOSURE,
        TestType.CROSS_SITE_REQUEST_FORGERY,
        TestType.INSECURE_OUTPUT_HANDLING,
        TestType.EXPOSED_DATABASE_DETAILS,
        TestType.FULL_PATH_DISCLOSURE
      ],
      attackParamLocations: [AttackParamLocation.HEADER]
    })
    .threshold(Severity.LOW)
    .timeout(40 * 60 * 1000)
    .run({
      method: HttpMethod.OPTIONS,
      url: `${process.env.BRIGHT_TARGET_URL}/api/users`
    });
});
