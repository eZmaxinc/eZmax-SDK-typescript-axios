# DocumenttypechecklistGetListV1ResponseMPayload

Payload for GET /1/object/documenttypechecklist/getList

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**iRowReturned** | **number** | The number of rows returned | [default to undefined]
**iRowFiltered** | **number** | The number of rows matching your filters (if any) or the total number of rows | [default to undefined]
**a_objDocumenttypechecklist** | [**Array&lt;DocumenttypechecklistListElement&gt;**](DocumenttypechecklistListElement.md) |  | [default to undefined]

## Example

```typescript
import { DocumenttypechecklistGetListV1ResponseMPayload } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: DocumenttypechecklistGetListV1ResponseMPayload = {
    iRowReturned,
    iRowFiltered,
    a_objDocumenttypechecklist,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
