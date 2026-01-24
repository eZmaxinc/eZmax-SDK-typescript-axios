# InvoiceGetCommunicationsendersV1Response

Response for GET /1/object/invoice/{pkiInvoiceID}/getCommunicationrecipients

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**objDebugPayload** | [**CommonResponseObjDebugPayload**](CommonResponseObjDebugPayload.md) |  | [default to undefined]
**objDebug** | [**CommonResponseObjDebug**](CommonResponseObjDebug.md) |  | [optional] [default to undefined]
**mPayload** | [**InvoiceGetCommunicationsendersV1ResponseMPayload**](InvoiceGetCommunicationsendersV1ResponseMPayload.md) |  | [default to undefined]

## Example

```typescript
import { InvoiceGetCommunicationsendersV1Response } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: InvoiceGetCommunicationsendersV1Response = {
    objDebugPayload,
    objDebug,
    mPayload,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
