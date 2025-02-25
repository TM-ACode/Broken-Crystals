import { SecRunner } from '@sectester/runner';
import { TestType, Severity, AttackParamLocation, HttpMethod } from '@sectester/scan';
import { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { AppModule } from '../src/app.module'; // Adjust the path as necessary

let app!: INestApplication;
let baseUrl!: string;
let runner!: SecRunner;

beforeAll(async () => {
  const moduleFixture = await Test.createTestingModule({
    imports: [AppModule],
  }).compile();

  app = moduleFixture.createNestApplication({
    logger: false,
  });
  await app.listen(0, '0.0.0.0');

  baseUrl = await app.getUrl();

  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME!
  });

  await runner.init();
});

afterAll(async () => {
  await runner.clear();
  await app.close();
});

jest.setTimeout(40 * 60 * 1000);

it('GET /api/partners/partnerLogin', async () => {
  await runner
    .createScan({
      name: expect.getState().currentTestName,
      tests: [TestType.XPATH_INJECTION],
      attackParamLocations: [AttackParamLocation.QUERY]
    })
    .threshold(Severity.LOW)
    .timeout(40 * 60 * 1000)
    .run({
      method: HttpMethod.GET,
      url: `${baseUrl}/api/partners/partnerLogin`,
      headers: { 'content-type': 'text/xml' },
      query: { username: 'walter100', password: 'Heisenberg123' }
    });
});
