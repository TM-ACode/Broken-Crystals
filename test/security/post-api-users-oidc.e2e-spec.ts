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

it('POST /api/users/oidc', async () => {
  await runner
    .createScan({
      tests: [
        TestType.EXCESSIVE_DATA_EXPOSURE,
        TestType.INSECURE_OUTPUT_HANDLING,
        TestType.EMAIL_INJECTION,
        TestType.LDAP_INJECTION,
        TestType.SECRET_TOKENS_LEAK,
        TestType.CROSS_SITE_REQUEST_FORGERY
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
      url: `${process.env.BRIGHT_TARGET_URL}/api/users/oidc`,
      body: {
        email: "john.doe@example.com",
        firstName: "John",
        lastName: "Doe",
        password: "password123"
      }
    });
});
