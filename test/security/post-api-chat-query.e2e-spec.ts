import { SecRunner } from '@sectester/runner';
import { Severity, TestType, AttackParamLocation, HttpMethod } from '@sectester/scan';

jest.setTimeout(15 * 60 * 1000); // 15 minutes

let runner!: SecRunner;

beforeEach(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME!
  });

  await runner.init();
});

afterEach(() => runner.clear());

it('POST /api/chat/query', async () => {
  await runner
    .createScan({
      name: expect.getState().currentTestName,
      tests: [
        TestType.CROSS_SITE_REQUEST_FORGERY,
        TestType.EXCESSIVE_DATA_EXPOSURE,
        TestType.HTML_INJECTION,
        TestType.SQL_INJECTION,
        TestType.CROSS_SITE_SCRIPTING,
        TestType.SERVER_SIDE_REQUEST_FORGERY,
        TestType.SERVER_SIDE_TEMPLATE_INJECTION,
        TestType.STORED_CROSS_SITE_SCRIPTING,
        TestType.UNVALIDATED_REDIRECT
      ],
      attackParamLocations: [AttackParamLocation.BODY]
    })
    .threshold(Severity.LOW)
    .timeout(15 * 60 * 1000)
    .run({
      method: HttpMethod.POST,
      url: `${process.env.BRIGHT_TARGET_URL}/api/chat/query`,
      body: [{"role":"user","content":"Hello!"}]
    });
});
