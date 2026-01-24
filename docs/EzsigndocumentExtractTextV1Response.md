# EzsigndocumentExtractTextV1Response

Response for POST /1/object/ezsigndocument/{pkiEzsigndocumentID}/extractText

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**objDebugPayload** | [**CommonResponseObjDebugPayload**](CommonResponseObjDebugPayload.md) |  | [default to undefined]
**objDebug** | [**CommonResponseObjDebug**](CommonResponseObjDebug.md) |  | [optional] [default to undefined]
**mPayload** | [**EzsigndocumentExtractTextV1ResponseMPayload**](EzsigndocumentExtractTextV1ResponseMPayload.md) |  | [default to undefined]

## Example

```typescript
import { EzsigndocumentExtractTextV1Response } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsigndocumentExtractTextV1Response = {
    objDebugPayload,
    objDebug,
    mPayload,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
