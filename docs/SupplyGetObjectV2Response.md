# SupplyGetObjectV2Response

Response for GET /2/object/supply/{pkiSupplyID}

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**objDebugPayload** | [**CommonResponseObjDebugPayload**](CommonResponseObjDebugPayload.md) |  | [default to undefined]
**objDebug** | [**CommonResponseObjDebug**](CommonResponseObjDebug.md) |  | [optional] [default to undefined]
**mPayload** | [**SupplyGetObjectV2ResponseMPayload**](SupplyGetObjectV2ResponseMPayload.md) |  | [default to undefined]

## Example

```typescript
import { SupplyGetObjectV2Response } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: SupplyGetObjectV2Response = {
    objDebugPayload,
    objDebug,
    mPayload,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
