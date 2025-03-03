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

it('GET /api/file/azure', async () => {
  await runner
    .createScan({
      tests: [
        TestType.EXCESSIVE_DATA_EXPOSURE,
        TestType.LOCAL_FILE_INCLUSION,
        TestType.REMOTE_FILE_INCLUSION,
        TestType.SERVER_SIDE_REQUEST_FORGERY,
        TestType.INSECURE_OUTPUT_HANDLING,
        TestType.FULL_PATH_DISCLOSURE
      ],
      attackParamLocations: [
        AttackParamLocation.QUERY,
        AttackParamLocation.HEADER
      ],
      skipStaticParams: false
    })
    .threshold(Severity.LOW)
    .timeout(40 * 60 * 1000)
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
