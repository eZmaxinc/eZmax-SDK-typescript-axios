# UserGetListV1ResponseMPayload

Payload for GET /1/object/user/getList

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**iRowReturned** | **number** | The number of rows returned | [default to undefined]
**iRowFiltered** | **number** | The number of rows matching your filters (if any) or the total number of rows | [default to undefined]
**a_objUser** | [**Array&lt;UserListElement&gt;**](UserListElement.md) |  | [default to undefined]

## Example

```typescript
import { UserGetListV1ResponseMPayload } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: UserGetListV1ResponseMPayload = {
    iRowReturned,
    iRowFiltered,
    a_objUser,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
