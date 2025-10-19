# SignatureGetObjectV2Response

Response for GET /2/object/signature/{pkiSignatureID}

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**objDebugPayload** | [**CommonResponseObjDebugPayload**](CommonResponseObjDebugPayload.md) |  | [default to undefined]
**objDebug** | [**CommonResponseObjDebug**](CommonResponseObjDebug.md) |  | [optional] [default to undefined]
**mPayload** | [**SignatureGetObjectV2ResponseMPayload**](SignatureGetObjectV2ResponseMPayload.md) |  | [default to undefined]

## Example

```typescript
import { SignatureGetObjectV2Response } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: SignatureGetObjectV2Response = {
    objDebugPayload,
    objDebug,
    mPayload,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
