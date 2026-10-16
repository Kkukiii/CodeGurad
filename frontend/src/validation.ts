const MAX_SOURCE_BYTES = 100_000;

export async function readSourceFile(file: File): Promise<string> {
  const extension = file.name.toLowerCase().split(".").pop();
  if (extension !== "py" && extension !== "java") {
    throw new Error("Choose a Python .py or Java .java file.");
  }
  if (file.size > MAX_SOURCE_BYTES) {
    throw new Error("This file is larger than the 100 KB review limit.");
  }
  const buffer = await file.arrayBuffer();
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(buffer);
  } catch {
    throw new Error("The file must be valid UTF-8 text.");
  }
}

export function validateSource(code: string, filename: string): void {
  const extension = filename.toLowerCase().split(".").pop();
  if (extension !== "py" && extension !== "java") {
    throw new Error("Use a .py or .java filename.");
  }
  if (new TextEncoder().encode(code).byteLength > MAX_SOURCE_BYTES) {
    throw new Error("Source exceeds the 100 KB review limit.");
  }
  if (!code.trim()) {
    throw new Error("Add source code before starting a review.");
  }
}
