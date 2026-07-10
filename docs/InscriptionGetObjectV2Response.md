# InscriptionGetObjectV2Response

Response for GET /2/object/inscription/{pkiInscriptionID}

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**objDebugPayload** | [**CommonResponseObjDebugPayload**](CommonResponseObjDebugPayload.md) |  | [default to undefined]
**objDebug** | [**CommonResponseObjDebug**](CommonResponseObjDebug.md) |  | [optional] [default to undefined]
**mPayload** | [**InscriptionGetObjectV2ResponseMPayload**](InscriptionGetObjectV2ResponseMPayload.md) |  | [default to undefined]

## Example

```typescript
import { InscriptionGetObjectV2Response } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: InscriptionGetObjectV2Response = {
    objDebugPayload,
    objDebug,
    mPayload,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
