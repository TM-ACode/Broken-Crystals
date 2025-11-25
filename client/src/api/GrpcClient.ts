import { createClient, createChannel } from 'nice-grpc-web';
import {
  ProductsServiceDefinition,
  type ProductsServiceClient
} from '../generated/products';
import {
  TestimonialsServiceDefinition,
  type TestimonialsServiceClient
} from '../generated/testimonials';
import {
  FileServiceDefinition,
  type FileServiceClient
} from '../generated/file';
import {
  OsServiceDefinition,
  type OsServiceClient
} from '../generated/os';

export class GrpcClient {
  private static instance: GrpcClient;

  public products: ProductsServiceClient;
  public testimonials: TestimonialsServiceClient;
  public file: FileServiceClient;
  public os: OsServiceClient;

  private constructor() {
    const baseUrl = import.meta.env.VITE_GRPC_URL || 'http://localhost:8081';
    const channel = createChannel(baseUrl);

    this.products = createClient(ProductsServiceDefinition, channel);
    this.testimonials = createClient(TestimonialsServiceDefinition, channel);
    this.file = createClient(FileServiceDefinition, channel);
    this.os = createClient(OsServiceDefinition, channel);
  }

  public static getInstance(): GrpcClient {
    if (!GrpcClient.instance) {
      GrpcClient.instance = new GrpcClient();
    }
    return GrpcClient.instance;
  }
}
