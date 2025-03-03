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

it('POST /api/render', async () => {
  await runner
    .createScan({
      tests: [
        TestType.SERVER_SIDE_TEMPLATE_INJECTION,
        TestType.XML_EXTERNAL_ENTITY_INJECTION,
        TestType.OS_COMMAND_INJECTION,
        TestType.SECRET_TOKENS_LEAK
      ],
      attackParamLocations: [AttackParamLocation.BODY]
    })
    .threshold(Severity.LOW)
    .timeout(40 * 60 * 1000)
    .run({
      method: HttpMethod.POST,
      url: `${process.env.BRIGHT_TARGET_URL}/api/render`,
      body: 'Write your text here',
      headers: {}
    });
});
