import { SecRunner } from '@sectester/runner';
import { Severity, TestType, AttackParamLocation, HttpMethod } from '@sectester/scan';

jest.setTimeout(40 * 60 * 1000); // 40 minutes

let runner!: SecRunner;

beforeEach(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME!
  });

  await runner.init();
});

afterEach(() => runner.clear());

it('POST /api/auth/jwt/jku/login', async () => {
  await runner
    .createScan({
      name: expect.getState().currentTestName,
      tests: [TestType.BROKEN_JWT_AUTHENTICATION, TestType.CROSS_SITE_SCRIPTING, TestType.SQL_INJECTION],
      attackParamLocations: [AttackParamLocation.BODY]
    })
    .threshold(Severity.LOW)
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
