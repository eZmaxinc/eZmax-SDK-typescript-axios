# CreditcardmerchantGetListV1ResponseMPayload

Payload for GET /1/object/creditcardmerchant/getList

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**iRowReturned** | **number** | The number of rows returned | [default to undefined]
**iRowFiltered** | **number** | The number of rows matching your filters (if any) or the total number of rows | [default to undefined]
**a_objCreditcardmerchant** | [**Array&lt;CreditcardmerchantListElement&gt;**](CreditcardmerchantListElement.md) |  | [default to undefined]

## Example

```typescript
import { CreditcardmerchantGetListV1ResponseMPayload } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: CreditcardmerchantGetListV1ResponseMPayload = {
    iRowReturned,
    iRowFiltered,
    a_objCreditcardmerchant,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
