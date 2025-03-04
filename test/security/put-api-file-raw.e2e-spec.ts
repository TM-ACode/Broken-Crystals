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

it('PUT /api/file/raw', async () => {
  await runner
    .createScan({
      tests: [TestType.DATE_MANIPULATION, TestType.CROSS_SITE_SCRIPTING],
      attackParamLocations: [AttackParamLocation.QUERY, AttackParamLocation.BODY],
      skipStaticParams: false // Required for date_manipulation test
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
