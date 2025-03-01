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

it('GET /api/file/aws', async () => {
  await runner
    .createScan({
      tests: [
        TestType.LOCAL_FILE_INCLUSION,
        TestType.REMOTE_FILE_INCLUSION,
        TestType.EXCESSIVE_DATA_EXPOSURE,
        TestType.SERVER_SIDE_REQUEST_FORGERY,
        TestType.IMPROPER_ASSET_MANAGEMENT
      ],
      attackParamLocations: [
        AttackParamLocation.QUERY,
        AttackParamLocation.HEADER
      ],
      skipStaticParams: false
    })
    .threshold(Severity.MEDIUM)
    .timeout(40 * 60 * 1000)
    .run({
      method: HttpMethod.GET,
      url: `${process.env.BRIGHT_TARGET_URL}/api/file/aws`,
      headers: {
        accept: 'image/jpg'
      },
      query: {
        path: 'config/products/crystals/amethyst.jpg',
        type: 'image/jpg'
      }
    });
});
