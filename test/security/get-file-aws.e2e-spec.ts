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
// Testing the /api/file/aws endpoint

describe('/api/file/aws', () => {
  it('should perform a security test for excessive data exposure and file inclusion', async () => {
    await runner
      .createScan({
        tests: [TestType.EXCESSIVE_DATA_EXPOSURE, TestType.LOCAL_FILE_INCLUSION, TestType.REMOTE_FILE_INCLUSION],
        name: expect.getState().currentTestName,
        attackParamLocations: [AttackParamLocation.QUERY],
        skipStaticParams: false
      })
      .threshold(Severity.LOW)
      .timeout(timeout)
      .run({
        method: HttpMethod.GET,
        url: `${process.env.BRIGHT_TARGET_URL}/api/file/aws`,
        headers: { accept: 'image/jpg' },
        query: {
          path: 'config/products/crystals/amethyst.jpg',
          type: 'image/jpg'
        }
      });
  });

  // Additional test cases can be added here
});

// Note: Ensure that the `BRIGHT_HOSTNAME` and `BRIGHT_TARGET_URL` environment variables are set correctly before running the tests.