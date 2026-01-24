# UserstagedCreateUserV1Response

Response for POST /1/object/userstaged/{pkiUserstagedID}/createUser

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**objDebugPayload** | [**CommonResponseObjDebugPayload**](CommonResponseObjDebugPayload.md) |  | [default to undefined]
**objDebug** | [**CommonResponseObjDebug**](CommonResponseObjDebug.md) |  | [optional] [default to undefined]
**mPayload** | [**UserstagedCreateUserV1ResponseMPayload**](UserstagedCreateUserV1ResponseMPayload.md) |  | [default to undefined]

## Example

```typescript
import { UserstagedCreateUserV1Response } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: UserstagedCreateUserV1Response = {
    objDebugPayload,
    objDebug,
    mPayload,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
