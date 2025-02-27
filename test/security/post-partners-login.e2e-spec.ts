import { Severity, TestType, AttackParamLocation, HttpMethod } from '@sectester/scan';
import { SecRunner } from '@sectester/runner';

jest.setTimeout(40 * 60 * 1000); // 40 minutes

let runner: SecRunner;

beforeEach(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME!
  });

  await runner.init();
});

afterEach(() => runner.clear());

it('POST /partners/login', async () => {
  await runner
    .createScan({
      name: expect.getState().currentTestName,
      tests: [
        TestType.CROSS_SITE_REQUEST_FORGERY,
        TestType.EXCESSIVE_DATA_EXPOSURE,
        TestType.INSECURE_OUTPUT_HANDLING,
        TestType.SQL_INJECTION,
        TestType.SECRET_TOKENS_LEAK,
        TestType.CROSS_SITE_SCRIPTING
      ],
      attackParamLocations: [AttackParamLocation.BODY]
    })
    .threshold(Severity.MEDIUM)
    .timeout(40 * 60 * 1000)
    .run({
      method: HttpMethod.POST,
      url: `${process.env.BRIGHT_TARGET_URL}/partners/login`,
      body: {
        username: 'sampleUser',
        password: 'samplePass'
      }
    });
});
