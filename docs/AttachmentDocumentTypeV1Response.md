# AttachmentDocumentTypeV1Response

Response for POST /1/object/attachment/{pkiAttachmentID}/documentType

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**objDebugPayload** | [**CommonResponseObjDebugPayload**](CommonResponseObjDebugPayload.md) |  | [default to undefined]
**objDebug** | [**CommonResponseObjDebug**](CommonResponseObjDebug.md) |  | [optional] [default to undefined]
**mPayload** | [**AttachmentDocumentTypeV1ResponseMPayload**](AttachmentDocumentTypeV1ResponseMPayload.md) |  | [default to undefined]

## Example

```typescript
import { AttachmentDocumentTypeV1Response } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: AttachmentDocumentTypeV1Response = {
    objDebugPayload,
    objDebug,
    mPayload,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
