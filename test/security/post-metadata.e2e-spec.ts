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

describe('POST /metadata', () => {
  it('should test security vulnerabilities', async () => {
    await runner
      .createScan({
        name: expect.getState().currentTestName,
        tests: [
          TestType.XML_EXTERNAL_ENTITY_INJECTION,
          TestType.CROSS_SITE_SCRIPTING,
          TestType.EXCESSIVE_DATA_EXPOSURE,
          TestType.SECRET_TOKENS_LEAK
        ],
        attackParamLocations: [AttackParamLocation.BODY, AttackParamLocation.HEADER]
      })
      .threshold(Severity.LOW)
      .timeout(15 * 60 * 1000)
      .run({
        method: HttpMethod.POST,
        url: `${process.env.BRIGHT_TARGET_URL}/api/metadata`,
        headers: { 'Content-Type': 'text/plain' },
        body: '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 915 585"><g stroke-width="3.45" fill="none"><path stroke="#000" d="M11.8 11.8h411v411l-411 .01v-411z"/><path stroke="#448" d="M489 11.7h415v411H489v-411z"/></g></svg>'
      });
  });
});
