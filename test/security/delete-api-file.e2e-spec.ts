import { Severity, TestType, AttackParamLocation, HttpMethod } from '@sectester/scan';
import { SecRunner } from '@sectester/runner';

jest.setTimeout(40 * 60 * 1000); // 40 minutes

let runner!: SecRunner;

beforeEach(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME!,
    projectId: process.env.BRIGHT_PROJECT_ID!
  });

  await runner.init();
});

afterEach(() => runner.clear());

it('DELETE /api/file', async () => {
  await runner
    .createScan({
      tests: [
        TestType.LOCAL_FILE_INCLUSION,
        TestType.REMOTE_FILE_INCLUSION,
        TestType.EXCESSIVE_DATA_EXPOSURE,
        TestType.FULL_PATH_DISCLOSURE,
        TestType.OS_COMMAND_INJECTION
      ],
      attackParamLocations: [AttackParamLocation.QUERY]
    })
    .threshold(Severity.LOW)
    .timeout(40 * 60 * 1000)
    .run({
      method: HttpMethod.DELETE,
      url: `${process.env.BRIGHT_TARGET_URL}/api/file`,
      query: { path: 'config/products/crystals/some_file.jpg' }
    });
});
