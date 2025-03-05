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

it('GET /api/auth/oidc-client', async () => {
  await runner
    .createScan({
      tests: [
        TestType.SENSITIVE_DATA_EXPOSURE,
        TestType.INFORMATION_DISCLOSURE,
        TestType.SECURITY_HEADERS
      ],
      attackParamLocations: [AttackParamLocation.HEADER]
    })
    .threshold(Severity.LOW)
    .timeout(40 * 60 * 1000)
    .run({
      method: HttpMethod.GET,
      url: `${process.env.BRIGHT_TARGET_URL}/api/auth/oidc-client`
    });
});
