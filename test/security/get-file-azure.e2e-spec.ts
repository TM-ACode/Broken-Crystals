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
// Testing the /api/file/azure endpoint

describe('/api/file/azure', () => {
  it('should perform a security test for file retrieval', async () => {
    await runner
      .createScan({
        tests: [
          TestType.LOCAL_FILE_INCLUSION,
          TestType.EXCESSIVE_DATA_EXPOSURE,
          TestType.SERVER_SIDE_REQUEST_FORGERY,
          TestType.IMPROPER_ASSET_MANAGEMENT,
          TestType.INSECURE_OUTPUT_HANDLING,
          TestType.FULL_PATH_DISCLOSURE
        ],
        name: expect.getState().currentTestName,
        attackParamLocations: [AttackParamLocation.QUERY],
        skipStaticParams: false
      })
      .threshold(Severity.LOW)
      .timeout(timeout)
      .run({
        method: HttpMethod.GET,
        url: `${process.env.BRIGHT_TARGET_URL}/api/file/azure`,
        headers: {
          accept: 'image/jpg'
        },
        query: {
          path: 'config/products/crystals/amethyst.jpg',
          type: 'image/jpg'
        }
      });
  });

  // Additional test cases can be added here
});

// Note: Ensure that the `BRIGHT_HOSTNAME` and `BRIGHT_TARGET_URL` environment variables are set correctly before running the tests.