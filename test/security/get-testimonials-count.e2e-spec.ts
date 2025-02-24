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

describe('GET /testimonials/count', () => {
  it('should test security vulnerabilities', async () => {
    await runner
      .createScan({
        name: expect.getState().currentTestName,
        tests: [TestType.SQL_INJECTION, TestType.EXCESSIVE_DATA_EXPOSURE, TestType.FULL_PATH_DISCLOSURE],
        attackParamLocations: [AttackParamLocation.QUERY]
      })
      .threshold(Severity.LOW)
      .timeout(15 * 60 * 1000)
      .run({
        method: HttpMethod.GET,
        url: `${process.env.BRIGHT_TARGET_URL}/api/testimonials/count`,
        query: { query: 'select count(*) as count from testimonial' },
        headers: { 'content-type': 'text/html' }
      });
  });
});