import { Controller, InternalServerErrorException } from '@nestjs/common';
import { GrpcMethod } from '@nestjs/microservices';
import { ProductsService } from '../products/products.service';

@Controller()
export class ProductsGrpcController {
  constructor(private readonly productsService: ProductsService) {}

  @GrpcMethod('ProductsService', 'ViewProduct')
  async viewProduct(data: { productName: string }): Promise<{ success: boolean }> {
    try {
      const query = `UPDATE product SET views_count = views_count + 1 WHERE name = '${data.productName}'`;
      await this.productsService.updateProduct(query);
      return { success: true };
    } catch (err) {
      throw new InternalServerErrorException({
        error: err.message,
        location: __filename,
      });
    }
  }
}
