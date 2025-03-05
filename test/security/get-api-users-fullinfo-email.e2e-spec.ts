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

it('GET /api/users/fullinfo/:email', async () => {
  await runner
    .createScan({
      tests: [
        TestType.SQL_INJECTION,
        TestType.INFORMATION_DISCLOSURE,
        TestType.EMAIL_ENUMERATION,
        TestType.INPUT_VALIDATION,
        TestType.ERROR_HANDLING
      ],
      attackParamLocations: [AttackParamLocation.QUERY]
    })
    .threshold(Severity.LOW)
    .timeout(40 * 60 * 1000)
    .run({
      method: HttpMethod.GET,
      url: `${process.env.BRIGHT_TARGET_URL}/api/users/fullinfo/john.doe@example.com`,
      query: { email: 'john.doe@example.com' }
    });
});
