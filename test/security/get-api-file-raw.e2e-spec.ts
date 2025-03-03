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

it('GET /api/file/raw', async () => {
  await runner
    .createScan({
      tests: [
        TestType.LOCAL_FILE_INCLUSION,
        TestType.FULL_PATH_DISCLOSURE,
        TestType.EXCESSIVE_DATA_EXPOSURE,
        TestType.SERVER_SIDE_REQUEST_FORGERY
      ],
      attackParamLocations: [AttackParamLocation.QUERY]
    })
    .threshold(Severity.LOW)
    .timeout(40 * 60 * 1000)
    .run({
      method: HttpMethod.GET,
      url: `${process.env.BRIGHT_TARGET_URL}/api/file/raw`,
      query: { path: 'config/products/crystals/amethyst.jpg' }
    });
});
