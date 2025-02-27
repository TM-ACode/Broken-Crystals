import { Severity, TestType, AttackParamLocation, HttpMethod } from '@sectester/scan';
import { SecRunner } from '@sectester/runner';

jest.setTimeout(40 * 60 * 1000); // 40 minutes

let runner!: SecRunner;

beforeEach(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME!
  });

  await runner.init();
});

afterEach(() => runner.clear());

it('GET /api/auth/oidc-client', async () => {
  await runner
    .createScan({
      name: expect.getState().currentTestName,
      tests: [
        TestType.EXCESSIVE_DATA_EXPOSURE,
        TestType.SECRET_TOKENS_LEAK,
        TestType.BROKEN_JWT_AUTHENTICATION,
        TestType.CROSS_SITE_REQUEST_FORGERY
      ],
      attackParamLocations: [AttackParamLocation.HEADER, AttackParamLocation.QUERY]
    })
    .threshold(Severity.LOW)
    .timeout(40 * 60 * 1000)
    .run({
      method: HttpMethod.GET,
      url: `${process.env.BRIGHT_TARGET_URL}/api/auth/oidc-client`
    });
});
