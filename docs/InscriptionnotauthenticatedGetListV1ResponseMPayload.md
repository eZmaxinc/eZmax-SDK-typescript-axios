# InscriptionnotauthenticatedGetListV1ResponseMPayload

Payload for GET /1/object/inscriptionnotauthenticated/getList

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**iRowReturned** | **number** | The number of rows returned | [default to undefined]
**iRowFiltered** | **number** | The number of rows matching your filters (if any) or the total number of rows | [default to undefined]
**a_objInscriptionnotauthenticated** | [**Array&lt;InscriptionnotauthenticatedListElement&gt;**](InscriptionnotauthenticatedListElement.md) |  | [default to undefined]

## Example

```typescript
import { InscriptionnotauthenticatedGetListV1ResponseMPayload } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: InscriptionnotauthenticatedGetListV1ResponseMPayload = {
    iRowReturned,
    iRowFiltered,
    a_objInscriptionnotauthenticated,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
