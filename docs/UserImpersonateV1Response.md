# UserImpersonateV1Response

Response for POST /1/object/user/{pkiUserID}/impersonate

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**objDebugPayload** | [**CommonResponseObjDebugPayload**](CommonResponseObjDebugPayload.md) |  | [default to undefined]
**objDebug** | [**CommonResponseObjDebug**](CommonResponseObjDebug.md) |  | [optional] [default to undefined]
**mPayload** | [**UserImpersonateV1ResponseMPayload**](UserImpersonateV1ResponseMPayload.md) |  | [default to undefined]

## Example

```typescript
import { UserImpersonateV1Response } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: UserImpersonateV1Response = {
    objDebugPayload,
    objDebug,
    mPayload,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
