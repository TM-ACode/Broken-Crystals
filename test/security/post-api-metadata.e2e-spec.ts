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

it('POST /api/metadata', async () => {
  await runner
    .createScan({
      tests: [
        TestType.XML_EXTERNAL_ENTITY_INJECTION,
        TestType.EXCESSIVE_DATA_EXPOSURE,
        TestType.INSECURE_OUTPUT_HANDLING
      ],
      attackParamLocations: [AttackParamLocation.BODY],
      skipStaticParams: false
    })
    .threshold(Severity.LOW)
    .timeout(40 * 60 * 1000)
    .run({
      method: HttpMethod.POST,
      url: `${process.env.BRIGHT_TARGET_URL}/api/metadata`,
      headers: {
        'content-type': 'text/xml'
      },
      body: `<?xml version="1.0" encoding="UTF-8"?>\n<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 915 585">\n  <g stroke-width="3.45" fill="none">\n    <path stroke="#000" d="M11.8 11.8h411v411l-411 .01v-411z"/>\n    <path stroke="#448" d="M489 11.7h415v411H489v-411z"/>\n  </g>\n</svg>`
    });
});
