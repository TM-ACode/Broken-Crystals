import { SecRunner } from '@sectester/runner';
import { TestType, Severity, AttackParamLocation, HttpMethod } from '@sectester/scan';

// Set a global timeout for all tests
const timeout = 40 * 60 * 1000; // 40 minutes
jest.setTimeout(timeout);

let runner: SecRunner;

beforeEach(async () => {
  // Initialize the SecRunner with the hostname from environment variables
  runner = new SecRunner({ hostname: process.env.BRIGHT_HOSTNAME! });
  await runner.init();
});

afterEach(() => runner.clear());

// Describe the test suite
// Testing DELETE /api/file endpoint

describe('/api/file', () => {
  it('should perform a security test for DELETE /api/file', async () => {
    await runner
      .createScan({
        tests: [
          TestType.LOCAL_FILE_INCLUSION,
          TestType.REMOTE_FILE_INCLUSION,
          TestType.OS_COMMAND_INJECTION,
          TestType.EXCESSIVE_DATA_EXPOSURE,
          TestType.FULL_PATH_DISCLOSURE,
          TestType.IMPROPER_ASSET_MANAGEMENT,
          TestType.EXPOSED_DATABASE_DETAILS,
          TestType.SECRET_TOKENS_LEAK
        ],
        name: expect.getState().currentTestName,
        attackParamLocations: [AttackParamLocation.QUERY],
        skipStaticParams: false
      })
      .threshold(Severity.LOW)
      .timeout(timeout)
      .run({
        method: HttpMethod.DELETE,
        url: `${process.env.BRIGHT_TARGET_URL}/api/file`,
        query: { path: 'config/products/crystals/some_file.jpg' }
      });
  });

  // Additional test cases can be added here
});

// Note: Ensure that the `BRIGHT_HOSTNAME` and `BRIGHT_TARGET_URL` environment variables are set correctly before running the tests.