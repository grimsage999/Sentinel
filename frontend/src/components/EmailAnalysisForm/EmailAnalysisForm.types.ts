import { AnalysisResult } from '../../types/analysis.types';
import { ApiError } from '../../types/api.types';

export interface EmailAnalysisFormProps {
  onAnalysisComplete?: (result: AnalysisResult) => void;
  onAnalysisError?: (error: ApiError) => void;
}

export interface EmailAnalysisFormState {
  emailContent: string;
  isAnalyzing: boolean;
  analysisResult: AnalysisResult | null;
  error: ApiError | null;
  validationError: string | null;
}

export interface FormValidationResult {
  isValid: boolean;
  error?: string;
}