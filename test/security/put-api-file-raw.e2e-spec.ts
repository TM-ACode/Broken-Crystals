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

// Test cases will be added here

describe('PUT /api/file/raw', () => {
  it('should test security vulnerabilities', async () => {
    await runner
      .createScan({
        name: expect.getState().currentTestName,
        tests: [
          TestType.LOCAL_FILE_INCLUSION,
          TestType.REMOTE_FILE_INCLUSION,
          TestType.EXCESSIVE_DATA_EXPOSURE,
          TestType.SECRET_TOKENS_LEAK,
          TestType.OS_COMMAND_INJECTION
        ],
        attackParamLocations: [
          AttackParamLocation.QUERY,
          AttackParamLocation.BODY
        ]
      })
      .threshold(Severity.LOW)
      .timeout(15 * 60 * 1000)
      .run({
        method: HttpMethod.PUT,
        url: `${process.env.BRIGHT_TARGET_URL}/api/file/raw`,
        query: { path: 'some/path/to/file.png' },
        body: 'raw file content'
      });
  });
});
