import { Module } from '@nestjs/common';
import { GitHubModule } from '../github/github.module.js';
import { SecurityController } from './security.controller.js';
import { ScanHistoryService } from './scan-history.service.js';
import { SecurityScannerService } from './security-scanner.service.js';

@Module({
  imports: [GitHubModule],
  controllers: [SecurityController],
  providers: [
    { provide: ScanHistoryService, useFactory: () => new ScanHistoryService() },
    SecurityScannerService,
  ],
})
export class SecurityModule {}