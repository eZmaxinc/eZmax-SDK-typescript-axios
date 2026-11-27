# CustomerGetCommunicationListV1Response

Response for GET /1/object/customer/{pkiCustomerID}/getCommunicationList

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**objDebugPayload** | [**CommonResponseObjDebugPayloadGetList**](CommonResponseObjDebugPayloadGetList.md) |  | [default to undefined]
**objDebug** | [**CommonResponseObjDebug**](CommonResponseObjDebug.md) |  | [optional] [default to undefined]
**mPayload** | [**CustomerGetCommunicationListV1ResponseMPayload**](CustomerGetCommunicationListV1ResponseMPayload.md) |  | [default to undefined]

## Example

```typescript
import { CustomerGetCommunicationListV1Response } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: CustomerGetCommunicationListV1Response = {
    objDebugPayload,
    objDebug,
    mPayload,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
