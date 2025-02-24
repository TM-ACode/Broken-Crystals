import { SecRunner } from '@sectester/runner';
import { Severity, TestType, AttackParamLocation, HttpMethod } from '@sectester/scan';

jest.setTimeout(15 * 60 * 1000); // 15 minutes

let runner!: SecRunner;

beforeEach(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME!
  });

  await runner.init();
});

afterEach(() => runner.clear());

// Test cases will be added here

describe('POST /api/users/oidc', () => {
  it('should test security vulnerabilities', async () => {
    await runner
      .createScan({
        name: expect.getState().currentTestName,
        tests: [
          TestType.CROSS_SITE_REQUEST_FORGERY,
          TestType.EXCESSIVE_DATA_EXPOSURE,
          TestType.FULL_PATH_DISCLOSURE,
          TestType.INSECURE_OUTPUT_HANDLING,
          TestType.LDAP_INJECTION,
          TestType.SQL_INJECTION,
          TestType.SECRET_TOKENS_LEAK,
          TestType.XML_EXTERNAL_ENTITY_INJECTION
        ],
        attackParamLocations: [
          AttackParamLocation.BODY,
          AttackParamLocation.HEADER
        ]
      })
      .threshold(Severity.LOW)
      .timeout(15 * 60 * 1000)
      .run({
        method: HttpMethod.POST,
        url: `${process.env.BRIGHT_TARGET_URL}/api/users/oidc`,
        headers: {},
        body: {
          email: 'john.doe@example.com',
          firstName: 'John',
          lastName: 'Doe',
          password: 'password123'
        }
      });
  });
});
