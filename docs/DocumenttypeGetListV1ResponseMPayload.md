# DocumenttypeGetListV1ResponseMPayload

Payload for GET /1/object/documenttype/getList

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**iRowReturned** | **number** | The number of rows returned | [default to undefined]
**iRowFiltered** | **number** | The number of rows matching your filters (if any) or the total number of rows | [default to undefined]
**a_objDocumenttype** | [**Array&lt;DocumenttypeListElement&gt;**](DocumenttypeListElement.md) |  | [default to undefined]

## Example

```typescript
import { DocumenttypeGetListV1ResponseMPayload } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: DocumenttypeGetListV1ResponseMPayload = {
    iRowReturned,
    iRowFiltered,
    a_objDocumenttype,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
