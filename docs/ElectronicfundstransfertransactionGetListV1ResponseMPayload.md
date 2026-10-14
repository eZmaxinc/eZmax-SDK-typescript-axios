# ElectronicfundstransfertransactionGetListV1ResponseMPayload

Payload for GET /1/object/electronicfundstransfertransaction/getList

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**iRowReturned** | **number** | The number of rows returned | [default to undefined]
**iRowFiltered** | **number** | The number of rows matching your filters (if any) or the total number of rows | [default to undefined]
**a_objElectronicfundstransfertransaction** | [**Array&lt;ElectronicfundstransfertransactionListElement&gt;**](ElectronicfundstransfertransactionListElement.md) |  | [default to undefined]

## Example

```typescript
import { ElectronicfundstransfertransactionGetListV1ResponseMPayload } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: ElectronicfundstransfertransactionGetListV1ResponseMPayload = {
    iRowReturned,
    iRowFiltered,
    a_objElectronicfundstransfertransaction,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
