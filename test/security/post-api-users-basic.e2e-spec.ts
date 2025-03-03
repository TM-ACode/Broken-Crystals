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

it('POST /api/users/basic', async () => {
  await runner
    .createScan({
      tests: [
        TestType.SQL_INJECTION,
        TestType.CROSS_SITE_SCRIPTING,
        TestType.MASS_ASSIGNMENT
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
      url: `${process.env.BRIGHT_TARGET_URL}/api/users/basic`,
      body: {
        email: "john.doe@example.com",
        firstName: "John",
        lastName: "Doe",
        password: "password123",
        op: "BASIC"
      }
    });
});
