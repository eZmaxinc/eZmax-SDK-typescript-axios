# CustomFormDataSignerResponse

A form Data Signer Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**fkiEzsignfoldersignerassociationID** | **number** | The unique ID of the Ezsignfoldersignerassociation | [default to undefined]
**fkiUserID** | **number** | The unique ID of the User | [optional] [default to undefined]
**sContactFirstname** | **string** | The First name of the contact | [default to undefined]
**sContactLastname** | **string** | The Last name of the contact | [default to undefined]
**a_objEzsignformfieldgroup** | [**Array&lt;CustomFormDataEzsignformfieldgroupResponse&gt;**](CustomFormDataEzsignformfieldgroupResponse.md) |  | [default to undefined]

## Example

```typescript
import { CustomFormDataSignerResponse } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: CustomFormDataSignerResponse = {
    fkiEzsignfoldersignerassociationID,
    fkiUserID,
    sContactFirstname,
    sContactLastname,
    a_objEzsignformfieldgroup,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
