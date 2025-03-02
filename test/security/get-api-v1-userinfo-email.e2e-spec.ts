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

it('GET /api/v1/userinfo/:email', async () => {
  await runner
    .createScan({
      tests: [
        TestType.EXCESSIVE_DATA_EXPOSURE,
        TestType.EMAIL_INJECTION,
        TestType.SQL_INJECTION,
        TestType.LDAP_INJECTION,
        TestType.INSECURE_OUTPUT_HANDLING
      ],
      attackParamLocations: [AttackParamLocation.PATH]
    })
    .threshold(Severity.LOW)
    .timeout(40 * 60 * 1000)
    .run({
      method: HttpMethod.GET,
      url: `${process.env.BRIGHT_TARGET_URL}/api/v1/userinfo/john.doe@example.com`
    });
});
