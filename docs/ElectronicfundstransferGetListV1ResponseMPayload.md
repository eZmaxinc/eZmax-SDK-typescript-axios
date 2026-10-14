# ElectronicfundstransferGetListV1ResponseMPayload

Payload for GET /1/object/electronicfundstransfer/getList

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**iRowReturned** | **number** | The number of rows returned | [default to undefined]
**iRowFiltered** | **number** | The number of rows matching your filters (if any) or the total number of rows | [default to undefined]
**a_objElectronicfundstransfer** | [**Array&lt;ElectronicfundstransferListElement&gt;**](ElectronicfundstransferListElement.md) |  | [default to undefined]

## Example

```typescript
import { ElectronicfundstransferGetListV1ResponseMPayload } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: ElectronicfundstransferGetListV1ResponseMPayload = {
    iRowReturned,
    iRowFiltered,
    a_objElectronicfundstransfer,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
