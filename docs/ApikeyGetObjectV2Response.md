# ApikeyGetObjectV2Response

Response for GET /2/object/apikey/{pkiApikeyID}

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**objDebugPayload** | [**CommonResponseObjDebugPayload**](CommonResponseObjDebugPayload.md) |  | [default to undefined]
**objDebug** | [**CommonResponseObjDebug**](CommonResponseObjDebug.md) |  | [optional] [default to undefined]
**mPayload** | [**ApikeyGetObjectV2ResponseMPayload**](ApikeyGetObjectV2ResponseMPayload.md) |  | [default to undefined]

## Example

```typescript
import { ApikeyGetObjectV2Response } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: ApikeyGetObjectV2Response = {
    objDebugPayload,
    objDebug,
    mPayload,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
