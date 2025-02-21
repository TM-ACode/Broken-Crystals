import { SecRunner } from '@sectester/runner';
import { TestType, Severity, AttackParamLocation, HttpMethod } from '@sectester/scan';
import { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { AppModule } from '../src/app.module';

let app: INestApplication;
let baseUrl: string;
let runner: SecRunner;

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
    hostname: process.env.BRIGHT_HOSTNAME!,
  });

  await runner.init();
});

afterAll(async () => {
  await runner.clear();
  await app.close();
});

describe('Security Tests', () => {
  const timeout = 600000;
  jest.setTimeout(timeout);

  beforeEach(async () => {
    // Setup logic if needed
  });

  afterEach(() => {
    // Teardown logic if needed
  });

  it('GET /api/email/sendSupportEmail', async () => {
    await runner
      .createScan({
        name: expect.getState().currentTestName,
        tests: [TestType.EMAIL_INJECTION],
        attackParamLocations: [AttackParamLocation.QUERY],
        threshold: Severity.LOW,
      })
      .timeout(timeout)
      .run({
        method: HttpMethod.GET,
        url: `${baseUrl}/api/email/sendSupportEmail`,
        headers: { 'Content-Type': 'application/json' },
        query: {
          name: 'Bob Dylan',
          to: 'username@email.com',
          subject: 'Help Request',
          content: 'I would like to request help regarding..',
        },
      });
  });
});
