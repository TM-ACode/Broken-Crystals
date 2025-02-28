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

it('DELETE /api/email/deleteEmails', async () => {
  await runner
    .createScan({
      tests: [
        TestType.HTTP_METHOD_FUZZING,
        TestType.EXCESSIVE_DATA_EXPOSURE,
        TestType.PROTO_POLLUTION,
        TestType.INSECURE_OUTPUT_HANDLING,
        TestType.OPEN_DATABASE,
        TestType.SSRF,
        TestType.CSRF
      ],
      attackParamLocations: [AttackParamLocation.BODY, AttackParamLocation.HEADER]
    })
    .threshold(Severity.LOW)
    .timeout(40 * 60 * 1000)
    .run({
      method: HttpMethod.DELETE,
      url: `${process.env.BRIGHT_TARGET_URL}/api/email/deleteEmails`
    });
});
