import { Controller, Post, Body, Inject, OnModuleInit } from '@nestjs/common';
import { ClientGrpc } from '@nestjs/microservices';
import { Observable } from 'rxjs';

interface ProductsService {
  viewProduct(data: { productName: string }): Observable<{ success: boolean }>;
}

interface TestimonialsService {
  testimonialsCount(data: { query: string }): Observable<{ count: number }>;
}

@Controller('api/grpc-bridge')
export class GrpcBridgeController implements OnModuleInit {
  private productsService: ProductsService;
  private testimonialsService: TestimonialsService;

  constructor(@Inject('GRPC_CLIENT') private client: ClientGrpc) {}

  onModuleInit() {
    this.productsService = this.client.getService<ProductsService>('ProductsService');
    this.testimonialsService = this.client.getService<TestimonialsService>('TestimonialsService');
  }

  @Post('view-product')
  viewProduct(@Body() body: { productName: string }) {
    return this.productsService.viewProduct(body);
  }

  @Post('testimonials-count')
  testimonialsCount(@Body() body: { query: string }) {
    return this.testimonialsService.testimonialsCount(body);
  }
}
