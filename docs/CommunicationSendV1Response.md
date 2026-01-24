# CommunicationSendV1Response

Response for POST /1/object/communication

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**objDebugPayload** | [**CommonResponseObjDebugPayload**](CommonResponseObjDebugPayload.md) |  | [default to undefined]
**objDebug** | [**CommonResponseObjDebug**](CommonResponseObjDebug.md) |  | [optional] [default to undefined]
**mPayload** | [**CommunicationSendV1ResponseMPayload**](CommunicationSendV1ResponseMPayload.md) |  | [default to undefined]

## Example

```typescript
import { CommunicationSendV1Response } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: CommunicationSendV1Response = {
    objDebugPayload,
    objDebug,
    mPayload,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
