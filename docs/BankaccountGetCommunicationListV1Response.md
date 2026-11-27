# BankaccountGetCommunicationListV1Response

Response for GET /1/object/bankaccount/{pkiBankaccountID}/getCommunicationList

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**objDebugPayload** | [**CommonResponseObjDebugPayloadGetList**](CommonResponseObjDebugPayloadGetList.md) |  | [default to undefined]
**objDebug** | [**CommonResponseObjDebug**](CommonResponseObjDebug.md) |  | [optional] [default to undefined]
**mPayload** | [**BankaccountGetCommunicationListV1ResponseMPayload**](BankaccountGetCommunicationListV1ResponseMPayload.md) |  | [default to undefined]

## Example

```typescript
import { BankaccountGetCommunicationListV1Response } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: BankaccountGetCommunicationListV1Response = {
    objDebugPayload,
    objDebug,
    mPayload,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
