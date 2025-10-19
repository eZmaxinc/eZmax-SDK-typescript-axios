# CustomerCreateObjectV1Response

Response for POST /1/object/customer

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**objDebugPayload** | [**CommonResponseObjDebugPayload**](CommonResponseObjDebugPayload.md) |  | [default to undefined]
**objDebug** | [**CommonResponseObjDebug**](CommonResponseObjDebug.md) |  | [optional] [default to undefined]
**mPayload** | [**CustomerCreateObjectV1ResponseMPayload**](CustomerCreateObjectV1ResponseMPayload.md) |  | [default to undefined]

## Example

```typescript
import { CustomerCreateObjectV1Response } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: CustomerCreateObjectV1Response = {
    objDebugPayload,
    objDebug,
    mPayload,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
