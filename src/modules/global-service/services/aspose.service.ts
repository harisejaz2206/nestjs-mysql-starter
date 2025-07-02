import {
  forwardRef,
  HttpException,
  HttpStatus,
  Inject,
  Injectable,
  InternalServerErrorException,
} from '@nestjs/common';
import { GlobalHttpRequestService } from '../modules/global-http-request-module/global-http-request.service';
import { ConfigService } from '@nestjs/config';
import { EnvKeysEnum } from 'src/modules/globals/enums/env.enum';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'fs';
import { join, resolve } from 'path';
import axios from 'axios';

@Injectable()
export class AsposeService {
  constructor(
    private readonly configService: ConfigService,
    private readonly httpClient: GlobalHttpRequestService,
  ) {}

  async authenticate(): Promise<any> {
    try {
      const data = new URLSearchParams({
        grant_type: 'client_credentials',
        client_id: this.configService.get(EnvKeysEnum.AsposeClientId),
        client_secret: this.configService.get(EnvKeysEnum.AsposeClientSecret),
      });
      const response = await this.httpClient.postRequest(
        this.configService.get(EnvKeysEnum.AsposeBaseUrl) + '/connect/token',
        data,
        {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
        },
      );

      return response.access_token;
    } catch (error) {
      throw new InternalServerErrorException(
        'Failed to create aspose client: ' + error.message,
      );
    }
  }

  async generateTemplate(
    testId: number,
    academyName: string,
    testDate: string,
    testTitle: string,
  ): Promise<any> {
    const token = await this.authenticate();
    const filePath = resolve('dist/src/omr.layout.json');
    // const filePath = resolve('src/omr.layout.json');

    if (!existsSync(filePath)) {
      throw Error('File does not exist at path:');
    }

    const jsonBuffer = readFileSync(filePath);
    const jsText = JSON.parse(jsonBuffer.toString());

    // Update template with test data
    jsText.children[0].children[3].children[0].children[1].value = testId;
    jsText.children[0].children[3].children[0].children[3].children[1].name = testTitle;
    jsText.children[0].children[3].children[0].children[4].children[1].name = testDate;
    jsText.children[0].children[3].children[0].children[5].children[1].name = academyName;

    const updatedJsonString = JSON.stringify(jsText);
    const base64Data = Buffer.from(updatedJsonString).toString('base64');

    const payload = {
      MarkupFile: base64Data,
      Images: {},
      Settings: {
        PaperSize: 'A4',
        BubbleColor: 'red',
      },
    };

    try {
      const response = await axios.post(
        `${this.configService.get(EnvKeysEnum.AsposeBaseUrl)}/v5.0/omr/GenerateTemplate/PostGenerateTemplate`,
        payload,
        {
          headers: {
            Accept: 'text/plain',
            'Content-Type': 'application/json',
            Authorization: `Bearer ${token}`,
          },
        },
      );

      const waitForTemplate = async (templateId: string) => {
        let attempts = 0;
        while (attempts < 5) {
          const template = await this.getTemplate(templateId, token);
          if (template.responseStatusCode != 'NotReady') return template;
          attempts++;
          await new Promise((resolve) => setTimeout(resolve, 5000));
        }
        throw new Error('Template generation timeout');
      };

      const answerSheet = await waitForTemplate(response.data);
      return answerSheet;
    } catch (error) {
      throw new HttpException(
        'Failed to generate OMR template',
        HttpStatus.BAD_REQUEST,
      );
    }
  }

  async getTemplate(id: string, token: string): Promise<any> {
    try {
      const response = await axios.get(
        `${this.configService.get(EnvKeysEnum.AsposeBaseUrl)}/v5.0/omr/GenerateTemplate/GetGenerateTemplate?id=${id}`,

        {
          headers: {
            Accept: 'text/plain',
            'Content-Type': 'application/json',
            Authorization: `Bearer ${token}`,
          },
        },
      );
      return response.data;
    } catch (error) {
      throw new HttpException(
        'Failed to get OMR template',
        HttpStatus.BAD_REQUEST,
      );
    }
  }

  async testSubmissionResult(
    imageBuffer: Buffer,
    testId: number,
    token: string,
  ) {
    const baseDir = join('storage', 'public', 'tests', testId.toString());
    const omrFilePath = join(baseDir, 'omr.txt');
    const omr64 = readFileSync(omrFilePath, 'utf8');

    const image64 = imageBuffer.toString('base64');

    const recognize = await this.recognition(image64, omr64, token);

    const waitForRecognition = async () => {
      let attempts = 0;
      while (attempts < 5) {
        const result = await this.getRecognition(recognize, token);
        if (result.responseStatusCode != 'NotReady') return result;
        attempts++;
        await new Promise((resolve) => setTimeout(resolve, 5000));
      }
      throw new Error('Template generation timeout');
    };
    const result = await waitForRecognition();
    return result;
  }

  async recognition(image: any, orm: any, token: string): Promise<any> {
    try {
      const payload = {
        Images: [image],
        omrFile: orm,
        outputFormat: 'Csv',
      };

      const response = await axios.post(
        `${this.configService.get(EnvKeysEnum.AsposeBaseUrl)}/v5.0/omr/RecognizeTemplate/PostRecognizeTemplate`,
        payload,
        {
          headers: {
            Accept: 'text/plain',
            'Content-Type': 'application/json',
            Authorization: `Bearer ${token}`,
          },
        },
      );
      return response.data;
    } catch (error) {
      console.log('error ', error);

      throw new HttpException(
        'Failed to get OMR template',
        HttpStatus.BAD_REQUEST,
      );
    }
  }

  async getRecognition(id: string, token: string): Promise<any> {
    try {
      const response = await axios.get(
        `${this.configService.get(EnvKeysEnum.AsposeBaseUrl)}/v5.0/omr/RecognizeTemplate/GetRecognizeTemplate?id=${id}`,

        {
          headers: {
            Accept: 'text/plain',
            'Content-Type': 'application/json',
            Authorization: `Bearer ${token}`,
          },
        },
      );

      return response.data;
    } catch (error) {
      console.log('error 1', error);

      throw new HttpException(
        'Failed to get OMR template',
        HttpStatus.BAD_REQUEST,
      );
    }
  }

  async extractImagesFromPDF(
    pdfBuffer: Buffer,
    pdfName: string,
    token: string,
  ): Promise<any> {
    try {
      // 1. Upload the PDF
      const uploadResponse = await axios.put(
        `${this.configService.get(EnvKeysEnum.AsposeBaseUrl)}/v3.0/pdf/storage/file/${pdfName}`,
        pdfBuffer,
        {
          headers: {
            'Content-Type': 'application/pdf',
            Authorization: `Bearer ${token}`,
          },
        },
      );

      // 2. Get the total page count
      const pagesCount = await this.getPageCount(pdfName, token);

      return pagesCount;
    } catch (error) {
      console.error('Error extracting images from PDF:', error);

      throw new HttpException(
        'Failed to extract images from PDF',
        HttpStatus.BAD_REQUEST,
      );
    }
  }

  async getPageCount(pdfName: string, token: string): Promise<any> {
    try {
      const response = await axios.get(
        `${this.configService.get(EnvKeysEnum.AsposeBaseUrl)}/v3.0/pdf/${pdfName}/pages`,

        {
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${token}`,
          },
        },
      );

      return response.data;
    } catch (error) {
      console.error('Error extracting images:', error);

      throw new HttpException(
        'Failed to extract images from PDF',
        HttpStatus.BAD_REQUEST,
      );
    }
  }

  async getImageId(
    pdfName: string,
    pageNo: number,
    token: string,
  ): Promise<any> {
    try {
      const response = await axios.get(
        `${this.configService.get(EnvKeysEnum.AsposeBaseUrl)}/v3.0/pdf/${pdfName}/pages/${pageNo}/images`,
        {
          headers: {
            Accept: 'application/json',
            'Content-Type': 'application/json',
            Authorization: `Bearer ${token}`,
          },
        },
      );

      return response.data;
    } catch (error) {
      console.error('Error extracting images:', error);

      throw new HttpException(
        'Failed to extract images from PDF',
        HttpStatus.BAD_REQUEST,
      );
    }
  }

  async getImage(
    pdfName: string,
    imageId: string,
    token: string,
  ): Promise<string> {
    try {
      const response = await axios.get(
        `${this.configService.get(EnvKeysEnum.AsposeBaseUrl)}/v3.0/pdf/${pdfName}/images/${imageId}/extract/png`,
        {
          headers: {
            Accept: 'application/json',
            'Content-Type': 'image/png',
            Authorization: `Bearer ${token}`,
          },
          responseType: 'arraybuffer', // Ensure that the response is in binary format
        },
      );

      // Convert binary data to base64 string
      const base64Image = Buffer.from(response.data, 'binary').toString(
        'base64',
      );

      return base64Image;
    } catch (error) {
      console.error('Error extracting images:', error);

      throw new HttpException(
        'Failed to extract images from PDF',
        HttpStatus.BAD_REQUEST,
      );
    }
  }
}
