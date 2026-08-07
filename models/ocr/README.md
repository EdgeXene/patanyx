# OCR model files

PP-OCRv3 detection + PP-OCRv4 English recognition, converted to ONNX and run
locally by `crates/ocr`. Nothing here touches a network at any point.

| File | What it is |
| --- | --- |
| `det.onnx` | text-region detection, input `[1,3,960,960]` |
| `rec.onnx` | text recognition, input `[1,3,48,320]`, 97 CTC classes |
| `rec_dict.txt` | 96 entries: 95 characters plus a trailing space |

**Licence: Apache-2.0**, code and weights, from Baidu's PP-OCR release. That
clearance is the reason these models were chosen over better-performing
alternatives with unclear commercial terms -- see XLiteOCR's
COMMERCIAL-USE.md, which did the audit.

## Do not regenerate these casually

The conversion has three traps that will silently produce a broken or
unloadable model. The full recipe, with the reasoning, is in
OCR-MODEL-CONVERSION.md, kept with the private build notes. In short:

1. `paddle2onnx` 2.1.0 cannot convert the detection model; use 1.3.1.
2. tract rejects dynamic axis names containing a dot, which is what
   paddle2onnx emits. Rename them before loading.
3. The raw rec export contains a malformed `Concat` that ONNX Runtime rejects
   too. `onnxsim` repairs it, and also bakes the 320 width in -- which is why
   `REC_WIDTH` is a constant rather than a parameter.

The dictionary order must match the model's class indices exactly. A mismatch
is caught loudly at load time by the class-count check, but a dictionary of
the RIGHT length in the WRONG order would not be, and would silently return
wrong characters.
