# AttachmentRestoreV1Response

Response for POST /1/object/attachment/{pkiAttachmentID}/restore

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**objDebugPayload** | [**CommonResponseObjDebugPayload**](CommonResponseObjDebugPayload.md) |  | [default to undefined]
**objDebug** | [**CommonResponseObjDebug**](CommonResponseObjDebug.md) |  | [optional] [default to undefined]
**mPayload** | [**AttachmentRestoreV1ResponseMPayload**](AttachmentRestoreV1ResponseMPayload.md) |  | [default to undefined]

## Example

```typescript
import { AttachmentRestoreV1Response } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: AttachmentRestoreV1Response = {
    objDebugPayload,
    objDebug,
    mPayload,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
