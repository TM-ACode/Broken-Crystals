import * as protobuf from 'protobufjs';

export class GrpcClient {
  private static instance: GrpcClient;
  private root: protobuf.Root;

  private constructor() {
    this.root = new protobuf.Root();
  }

  public static async getInstance(): Promise<GrpcClient> {
    if (!GrpcClient.instance) {
      GrpcClient.instance = new GrpcClient();
      await GrpcClient.instance.loadProtos();
    }
    return GrpcClient.instance;
  }

  private async loadProtos() {
    const productsProto = `
    syntax = "proto3";
    package products;
    service ProductsService {
      rpc ViewProduct (ViewProductRequest) returns (ViewProductResponse);
    }
    message ViewProductRequest {
      string productName = 1;
    }
    message ViewProductResponse {
      bool success = 1;
    }
    `;

    const testimonialsProto = `
    syntax = "proto3";
    package testimonials;
    service TestimonialsService {
      rpc TestimonialsCount (TestimonialsCountRequest) returns (TestimonialsCountResponse);
    }
    message TestimonialsCountRequest {
      string query = 1;
    }
    message TestimonialsCountResponse {
      int32 count = 1;
    }
    `;

    protobuf.parse(productsProto, this.root);
    protobuf.parse(testimonialsProto, this.root);
  }

  public async call(
    packageName: string,
    service: string,
    method: string,
    requestData: any
  ): Promise<any> {
    if (!this.root) {
      await this.loadProtos();
    }

    const RequestType = this.root.lookupType(
      packageName + '.' + method + 'Request'
    );
    const ResponseType = this.root.lookupType(
      packageName + '.' + method + 'Response'
    );

    const errMsg = RequestType.verify(requestData);
    if (errMsg) throw Error(errMsg);

    const message = RequestType.create(requestData);
    const buffer = RequestType.encode(message).finish();

    // Create gRPC-Web frame
    // 1 byte flag (0) + 4 bytes length (big endian) + data
    const frame = new Uint8Array(5 + buffer.length);
    frame[0] = 0;
    const len = buffer.length;
    frame[1] = (len >> 24) & 0xff;
    frame[2] = (len >> 16) & 0xff;
    frame[3] = (len >> 8) & 0xff;
    frame[4] = len & 0xff;
    frame.set(buffer, 5);

    const baseUrl = 'http://localhost:8081';
    const url = `${baseUrl}/${packageName}.${service}/${method}`;

    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'content-type': 'application/grpc-web+proto',
        'x-grpc-web': '1'
      },
      body: frame
    });

    if (!response.ok) {
      throw new Error(`gRPC call failed: ${response.statusText}`);
    }

    const responseBuffer = await response.arrayBuffer();
    const responseData = new Uint8Array(responseBuffer);

    let offset = 0;
    while (offset < responseData.length) {
      const flag = responseData[offset];
      const length =
        (responseData[offset + 1] << 24) |
        (responseData[offset + 2] << 16) |
        (responseData[offset + 3] << 8) |
        responseData[offset + 4];

      if (flag === 0) {
        // Data frame
        const data = responseData.slice(offset + 5, offset + 5 + length);
        return ResponseType.decode(data);
      } else if (flag === 0x80) {
        // Trailers, ignore for now
      }
      offset += 5 + length;
    }

    throw new Error('No data found in response');
  }
}
