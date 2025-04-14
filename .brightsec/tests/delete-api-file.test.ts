import { test, before, after } from 'node:test';
import { Severity, AttackParamLocation, HttpMethod } from '@sectester/scan';
// Other setup and teardown logic from the test skeleton

const timeout = 40 * 60 * 1000;
const baseUrl = process.env.BRIGHT_TARGET_URL!;

// Test for DELETE /api/file

test('DELETE /api/file', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['lfi', 'bopla', 'ssrf', 'open_cloud_storage', 'secret_tokens'],
      attackParamLocations: [AttackParamLocation.QUERY]
    })
    .threshold(Severity.CRITICAL)
    .timeout(timeout)
    .run({
      method: HttpMethod.DELETE,
      url: `${baseUrl}/api/file`,
      query: {
        path: 'config/products/crystals/some_file.jpg'
      }
    });
});
