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

it('POST /api/auth/jwt/kid-sql/login', async () => {
  await runner
    .createScan({
      tests: [
        TestType.SQL_INJECTION,
        TestType.EXCESSIVE_DATA_EXPOSURE,
        TestType.INSECURE_OUTPUT_HANDLING,
        TestType.SECRET_TOKENS_LEAK
      ],
      attackParamLocations: [
        AttackParamLocation.BODY
      ],
      skipStaticParams: false
    })
    .threshold(Severity.LOW)
    .timeout(40 * 60 * 1000)
    .run({
      method: HttpMethod.POST,
      url: `${process.env.BRIGHT_TARGET_URL}/api/auth/jwt/kid-sql/login`,
      body: {
        user: 'example@example.com',
        password: 'password123'
      }
    });
});
