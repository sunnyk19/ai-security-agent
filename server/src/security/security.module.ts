import { Module } from '@nestjs/common';
import { GitHubModule } from '../github/github.module.js';
import { SecurityController } from './security.controller.js';
import { SecurityScannerService } from './security-scanner.service.js';

@Module({
  imports: [GitHubModule],
  controllers: [SecurityController],
  providers: [SecurityScannerService],
})
export class SecurityModule {}