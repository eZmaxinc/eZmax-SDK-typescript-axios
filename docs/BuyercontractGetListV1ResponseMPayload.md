# BuyercontractGetListV1ResponseMPayload

Payload for GET /1/object/buyercontract/getList

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**iRowReturned** | **number** | The number of rows returned | [default to undefined]
**iRowFiltered** | **number** | The number of rows matching your filters (if any) or the total number of rows | [default to undefined]
**a_objBuyercontract** | [**Array&lt;BuyercontractListElement&gt;**](BuyercontractListElement.md) |  | [default to undefined]

## Example

```typescript
import { BuyercontractGetListV1ResponseMPayload } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: BuyercontractGetListV1ResponseMPayload = {
    iRowReturned,
    iRowFiltered,
    a_objBuyercontract,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
