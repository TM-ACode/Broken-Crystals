import { Severity, TestType, AttackParamLocation, HttpMethod } from '@sectester/scan';
import { SecRunner } from '@sectester/runner';

jest.setTimeout(40 * 60 * 1000); // 40 minutes

let runner!: SecRunner;

beforeEach(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME!
  });

  await runner.init();
});

afterEach(() => runner.clear());

it('PUT /api/file/raw', async () => {
  await runner
    .createScan({
      name: expect.getState().currentTestName,
      tests: [
        TestType.FILE_UPLOAD,
        TestType.LOCAL_FILE_INCLUSION,
        TestType.EXCESSIVE_DATA_EXPOSURE,
        TestType.INSECURE_OUTPUT_HANDLING,
        TestType.FULL_PATH_DISCLOSURE
      ],
      attackParamLocations: [
        AttackParamLocation.QUERY,
        AttackParamLocation.BODY
      ]
    })
    .threshold(Severity.LOW)
    .timeout(40 * 60 * 1000)
    .run({
      method: HttpMethod.PUT,
      url: `${process.env.BRIGHT_TARGET_URL}/api/file/raw`,
      query: { path: 'some/path/to/file.png' },
      body: '<raw file content>'
    });
});
