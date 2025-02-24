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

describe('GET /api/file', () => {
  it('should test security vulnerabilities', async () => {
    await runner
      .createScan({
        name: 'GET /api/file',
        tests: [
          TestType.LOCAL_FILE_INCLUSION,
          TestType.EXCESSIVE_DATA_EXPOSURE,
          TestType.EXPOSED_DATABASE_DETAILS,
          TestType.SERVER_SIDE_REQUEST_FORGERY,
          TestType.UNVALIDATED_REDIRECT
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
        url: `${process.env.BRIGHT_TARGET_URL}/api/file`,
        headers: { accept: 'image/jpg' },
        query: { path: 'config/products/crystals/amethyst.jpg', type: 'image/jpg' }
      });
  });
});
