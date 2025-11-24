import { MiddlewareConsumer, Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AuthModule } from './auth/auth.module';
import { UsersModule } from './users/users.module';
import { FileModule } from './file/file.module';
import { SubscriptionsModule } from './subscriptions/subscriptions.module';
import { TestimonialsModule } from './testimonials/testimonials.module';
import { ProductsModule } from './products/products.module';
import { OrmModule } from './orm/orm.module';
import { ConfigModule } from '@nestjs/config';
import { HttpClientService } from './httpclient/httpclient.service';
import { HttpClientModule as HttpClientModule } from './httpclient/httpclient.module';
import { TraceMiddleware } from './components/trace.middleware';
import { GraphQLModule } from '@nestjs/graphql';
import { MercuriusDriver, MercuriusDriverConfig } from '@nestjs/mercurius';
import { ClientsModule, Transport } from '@nestjs/microservices';
import { join } from 'path';
import { GrpcBridgeController } from './grpc/grpc.bridge.controller';

@Module({
  imports: [
    OrmModule,
    AuthModule,
    UsersModule,
    FileModule,
    SubscriptionsModule,
    TestimonialsModule,
    ProductsModule,
    ConfigModule.forRoot({
      isGlobal: true,
    }),
    HttpClientModule,
    GraphQLModule.forRoot<MercuriusDriverConfig>({
      driver: MercuriusDriver,
      graphiql: true,
      autoSchemaFile: true,
    }),
    ClientsModule.register([
      {
        name: 'GRPC_CLIENT',
        transport: Transport.GRPC,
        options: {
          package: ['products', 'testimonials'],
          protoPath: [
            join(__dirname, 'grpc/products.proto'),
            join(__dirname, 'grpc/testimonials.proto'),
          ],
          url: '0.0.0.0:5000',
        },
      },
    ]),
  ],
  controllers: [AppController, GrpcBridgeController],
  providers: [HttpClientService],
})
export class AppModule {
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(TraceMiddleware).forRoutes('(.*)');
  }
}
