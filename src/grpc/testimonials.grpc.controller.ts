import { Controller } from '@nestjs/common';
import { GrpcMethod } from '@nestjs/microservices';
import { TestimonialsService } from '../testimonials/testimonials.service';

@Controller()
export class TestimonialsGrpcController {
  constructor(private readonly testimonialsService: TestimonialsService) {}

  @GrpcMethod('TestimonialsService', 'TestimonialsCount')
  async testimonialsCount(data: { query: string }): Promise<{ count: number }> {
    const count = await this.testimonialsService.count(data.query);
    return { count };
  }
}
