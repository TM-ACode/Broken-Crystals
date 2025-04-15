import { test, before, after } from 'node:test';
import { SecRunner } from '@sectester/runner';
import { Severity, AttackParamLocation, HttpMethod } from '@sectester/scan';

let runner!: SecRunner;

const timeout = 40 * 60 * 1000; // 40 minutes
const baseUrl = process.env.BRIGHT_TARGET_URL!;

before(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME!,
    projectId: process.env.BRIGHT_PROJECT_ID!
  });

  await runner.init();
});

after(() => runner.clear());

// Test for POST /api/auth/admin/login

test('POST /api/auth/admin/login', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['csrf', 'sqli', 'jwt', 'osi', 'unvalidated_redirect'],
      attackParamLocations: [AttackParamLocation.BODY],
      skipStaticParams: false // Only relevant for date_manipulation, not used here
    })
    .threshold(Severity.CRITICAL)
    .timeout(timeout)
    .run({
      method: HttpMethod.POST,
      url: `${baseUrl}/api/auth/admin/login`,
      body: {
        user: "example@example.com",
        password: "password123"
      },
      headers: { 'Content-Type': 'application/json' }
    });
});
