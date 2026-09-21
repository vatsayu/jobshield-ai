
export type AnalysisType = "url" | "message" | "email";

export type RiskCategory =
  | "unknown"
  | "low"
  | "medium"
  | "high"
  | "critical";

export type AnalysisStatus =
  | "queued"
  | "processing"
  | "completed"
  | "failed";

export type EvidenceStatus =
  | "detected"
  | "verified"
  | "unverified"
  | "insufficient_evidence";

export type EvidenceSource =
  | "deterministic_analysis"
  | "external_verification"
  | "user_provided"
  | "ai_analysis";

export interface EvidenceItem {
  category: string;
  signal: string;
  explanation: string;
  severity: RiskCategory;
  status: EvidenceStatus;
  source: EvidenceSource;
}

export interface AnalysisResponse {
  analysis_id: string;
  analysis_type: AnalysisType;
  status: AnalysisStatus;
  risk_category: RiskCategory;
  risk_score: number;
  summary: string;
  evidence: EvidenceItem[];
  recommended_actions: string[];
}

export interface EmailAnalysisPayload {
  subject?: string;
  sender?: string;
  reply_to?: string;
  body: string;
}

const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://127.0.0.1:8000";

async function request<T>(
  endpoint: string,
  payload: unknown,
): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${endpoint}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    let message = `Request failed with status ${response.status}`;

    try {
      const errorBody = await response.json();

      if (typeof errorBody.detail === "string") {
        message = errorBody.detail;
      } else if (Array.isArray(errorBody.detail)) {
        message = "Please check the submitted input.";
      }
    } catch {
      // Keep the default error message when the response is not JSON.
    }

    throw new Error(message);
  }

  return response.json() as Promise<T>;
}

export function analyzeURL(
  url: string,
): Promise<AnalysisResponse> {
  return request<AnalysisResponse>("/api/v1/analyze/url", {
    url,
  });
}

export function analyzeMessage(
  message: string,
): Promise<AnalysisResponse> {
  return request<AnalysisResponse>("/api/v1/analyze/message", {
    message,
  });
}

export function analyzeEmail(
  payload: EmailAnalysisPayload,
): Promise<AnalysisResponse> {
  return request<AnalysisResponse>("/api/v1/analyze/email", payload);
}