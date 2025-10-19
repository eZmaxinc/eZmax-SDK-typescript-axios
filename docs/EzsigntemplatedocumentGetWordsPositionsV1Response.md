# EzsigntemplatedocumentGetWordsPositionsV1Response

Response for POST /1/object/ezsigntemplatedocument/{pkiEzsigntemplatedocumentID}/getWordsPositions

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**objDebugPayload** | [**CommonResponseObjDebugPayload**](CommonResponseObjDebugPayload.md) |  | [default to undefined]
**objDebug** | [**CommonResponseObjDebug**](CommonResponseObjDebug.md) |  | [optional] [default to undefined]
**mPayload** | [**Array&lt;CustomWordPositionWordResponse&gt;**](CustomWordPositionWordResponse.md) | Payload for POST /1/object/ezsigntemplatedocument/{pkiEzsigntemplatedocumentID}/getWordsPositions | [default to undefined]

## Example

```typescript
import { EzsigntemplatedocumentGetWordsPositionsV1Response } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsigntemplatedocumentGetWordsPositionsV1Response = {
    objDebugPayload,
    objDebug,
    mPayload,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
