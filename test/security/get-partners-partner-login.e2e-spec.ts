import { SecRunner } from '@sectester/runner';
import { TestType, Severity, AttackParamLocation, HttpMethod } from '@sectester/scan';

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

describe('GET /partners/partnerLogin', () => {
  it('should test security vulnerabilities', async () => {
    await runner
      .createScan({
        name: expect.getState().currentTestName,
        tests: [
          TestType.XPATH_INJECTION,
          TestType.EXCESSIVE_DATA_EXPOSURE,
          TestType.EXPOSED_DATABASE_DETAILS,
          TestType.INSECURE_OUTPUT_HANDLING,
          TestType.SECRET_TOKENS_LEAK
        ],
        attackParamLocations: [
          AttackParamLocation.QUERY,
          AttackParamLocation.HEADER
        ]
      })
      .threshold(Severity.LOW)
      .timeout(15 * 60 * 1000)
      .run({
        method: HttpMethod.GET,
        url: `${process.env.BRIGHT_TARGET_URL}/api/partners/partnerLogin`,
        headers: { 'content-type': 'text/xml' },
        query: { username: 'walter100', password: 'Heisenberg123' }
      });
  });
});
