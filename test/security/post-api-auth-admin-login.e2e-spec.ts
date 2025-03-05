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

it('POST /api/auth/admin/login', async () => {
  await runner
    .createScan({
      tests: [
        TestType.SQL_INJECTION,
        TestType.CROSS_SITE_SCRIPTING,
        TestType.CSRF,
        TestType.SENSITIVE_DATA_EXPOSURE,
        TestType.IMPROPER_ERROR_HANDLING,
        TestType.WEAK_PASSWORD_POLICY,
        TestType.JWT_SECURITY
      ],
      attackParamLocations: [AttackParamLocation.BODY]
    })
    .threshold(Severity.LOW)
    .timeout(40 * 60 * 1000)
    .run({
      method: HttpMethod.POST,
      url: `${process.env.BRIGHT_TARGET_URL}/api/auth/admin/login`,
      body: {
        user: 'example@example.com',
        password: 'password123'
      }
    });
});
