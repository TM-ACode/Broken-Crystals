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

it('POST /api/auth/jwt/jku/login', async () => {
  await runner
    .createScan({
      tests: [
        TestType.JWT_MANIPULATION,
        TestType.PASSWORD_SECURITY,
        TestType.SENSITIVE_DATA_EXPOSURE,
        TestType.ERROR_HANDLING
      ],
      attackParamLocations: [
        AttackParamLocation.BODY,
        AttackParamLocation.HEADER
      ],
      skipStaticParams: false
    })
    .threshold(Severity.MEDIUM)
    .timeout(40 * 60 * 1000)
    .run({
      method: HttpMethod.POST,
      url: `${process.env.BRIGHT_TARGET_URL}/api/auth/jwt/jku/login`,
      body: {
        user: 'example@example.com',
        password: 'password123'
      }
    });
});
