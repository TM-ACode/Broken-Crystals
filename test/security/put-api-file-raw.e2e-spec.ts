import { SecRunner } from '@sectester/runner';
import { Severity, AttackParamLocation, HttpMethod } from '@sectester/scan';

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

it('PUT /api/file/raw', async () => {
  await runner
    .createScan({
      tests: ['file_upload', 'http_method_fuzzing'],
      attackParamLocations: [AttackParamLocation.BODY, AttackParamLocation.QUERY]
    })
    .threshold(Severity.CRITICAL)
    .timeout(40 * 60 * 1000)
    .run({
      method: HttpMethod.PUT,
      url: `${process.env.BRIGHT_TARGET_URL}/api/file/raw`,
      query: { path: 'some/path/to/file.png' },
      body: '<raw file content>'
    });
});
