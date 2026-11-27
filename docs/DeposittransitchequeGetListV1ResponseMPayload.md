# DeposittransitchequeGetListV1ResponseMPayload

Payload for GET /1/object/deposittransitcheque/getList

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**iRowReturned** | **number** | The number of rows returned | [default to undefined]
**iRowFiltered** | **number** | The number of rows matching your filters (if any) or the total number of rows | [default to undefined]
**a_objDeposittransitcheque** | [**Array&lt;DeposittransitchequeListElement&gt;**](DeposittransitchequeListElement.md) |  | [default to undefined]

## Example

```typescript
import { DeposittransitchequeGetListV1ResponseMPayload } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: DeposittransitchequeGetListV1ResponseMPayload = {
    iRowReturned,
    iRowFiltered,
    a_objDeposittransitcheque,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
