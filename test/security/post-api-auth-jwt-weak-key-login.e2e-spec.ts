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

it('POST /api/auth/jwt/weak-key/login', async () => {
  await runner
    .createScan({
      tests: [
        TestType.BROKEN_JWT_AUTHENTICATION,
        TestType.EXCESSIVE_DATA_EXPOSURE,
        TestType.SECRET_TOKENS_LEAK
      ],
      attackParamLocations: [AttackParamLocation.BODY]
    })
    .threshold(Severity.LOW)
    .timeout(40 * 60 * 1000)
    .run({
      method: HttpMethod.POST,
      url: `${process.env.BRIGHT_TARGET_URL}/api/auth/jwt/weak-key/login`,
      body: {
        user: 'example@example.com',
        password: 'password123'
      }
    });
});
