import { createClient, createChannel } from 'nice-grpc-web';
import {
  ProductsServiceDefinition,
  type ProductsServiceClient
} from '../generated/products';
import {
  TestimonialsServiceDefinition,
  type TestimonialsServiceClient
} from '../generated/testimonials';

export class GrpcClient {
  private static instance: GrpcClient;

  public products: ProductsServiceClient;
  public testimonials: TestimonialsServiceClient;

  private constructor() {
    const baseUrl = import.meta.env.VITE_GRPC_URL || 'http://localhost:8081';
    const channel = createChannel(baseUrl);

    this.products = createClient(ProductsServiceDefinition, channel);
    this.testimonials = createClient(TestimonialsServiceDefinition, channel);
  }

  public static getInstance(): GrpcClient {
    if (!GrpcClient.instance) {
      GrpcClient.instance = new GrpcClient();
    }
    return GrpcClient.instance;
  }
}
