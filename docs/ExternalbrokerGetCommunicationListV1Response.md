# ExternalbrokerGetCommunicationListV1Response

Response for GET /1/object/externalbroker/{pkiExternalbrokerID}/getCommunicationList

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**objDebugPayload** | [**CommonResponseObjDebugPayloadGetList**](CommonResponseObjDebugPayloadGetList.md) |  | [default to undefined]
**objDebug** | [**CommonResponseObjDebug**](CommonResponseObjDebug.md) |  | [optional] [default to undefined]
**mPayload** | [**ExternalbrokerGetCommunicationListV1ResponseMPayload**](ExternalbrokerGetCommunicationListV1ResponseMPayload.md) |  | [default to undefined]

## Example

```typescript
import { ExternalbrokerGetCommunicationListV1Response } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: ExternalbrokerGetCommunicationListV1Response = {
    objDebugPayload,
    objDebug,
    mPayload,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
