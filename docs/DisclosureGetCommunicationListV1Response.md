# DisclosureGetCommunicationListV1Response

Response for GET /1/object/disclosure/{pkiDisclosureID}/getCommunicationList

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**objDebugPayload** | [**CommonResponseObjDebugPayloadGetList**](CommonResponseObjDebugPayloadGetList.md) |  | [default to undefined]
**objDebug** | [**CommonResponseObjDebug**](CommonResponseObjDebug.md) |  | [optional] [default to undefined]
**mPayload** | [**DisclosureGetCommunicationListV1ResponseMPayload**](DisclosureGetCommunicationListV1ResponseMPayload.md) |  | [default to undefined]

## Example

```typescript
import { DisclosureGetCommunicationListV1Response } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: DisclosureGetCommunicationListV1Response = {
    objDebugPayload,
    objDebug,
    mPayload,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
