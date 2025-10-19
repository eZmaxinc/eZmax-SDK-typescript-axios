# EzsigndocumentGetWordsPositionsV1Response

Response for POST /1/object/ezsigndocument/{pkiEzsigndocumentID}/getWordsPositions

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**objDebugPayload** | [**CommonResponseObjDebugPayload**](CommonResponseObjDebugPayload.md) |  | [default to undefined]
**objDebug** | [**CommonResponseObjDebug**](CommonResponseObjDebug.md) |  | [optional] [default to undefined]
**mPayload** | [**Array&lt;CustomWordPositionWordResponse&gt;**](CustomWordPositionWordResponse.md) | Payload for POST /1/object/ezsigndocument/{pkiEzsigndocumentID}/getWordsPositions | [default to undefined]

## Example

```typescript
import { EzsigndocumentGetWordsPositionsV1Response } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsigndocumentGetWordsPositionsV1Response = {
    objDebugPayload,
    objDebug,
    mPayload,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
