import { SecRunner } from '@sectester/runner';
import { Severity, AttackParamLocation, HttpMethod } from '@sectester/scan';

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

it('PUT /api/file/raw', async () => {
  const baseUrl = process.env.BRIGHT_TARGET_URL;
  await runner
    .createScan({
      tests: ['file_upload', 'lfi', 'ssrf', 'excessive_data_exposure', 'osi'],
      attackParamLocations: [AttackParamLocation.BODY, AttackParamLocation.PATH]
    })
    .threshold(Severity.CRITICAL)
    .timeout(40 * 60 * 1000)
    .run({
      method: HttpMethod.PUT,
      url: `${baseUrl}/api/file/raw`,
      query: { path: 'some/path/to/file.png' },
      body: '<file content>'
    });
});
