# EzsignfoldersignerassociationResponseCompoundUser

A Ezsignfoldersignerassociation->User Object and children to create a complete structure

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiUserID** | **number** | The unique ID of the User | [default to undefined]
**fkiLanguageID** | **number** | The unique ID of the Language.  Valid values:  |Value|Description| |-|-| |1|French| |2|English| | [default to undefined]
**sUserFirstname** | **string** | The first name of the user | [default to undefined]
**sUserLastname** | **string** | The last name of the user | [default to undefined]
**sEmailAddress** | **string** | The email address. | [default to undefined]
**eUserType** | [**FieldEUserType**](FieldEUserType.md) |  | [default to undefined]

## Example

```typescript
import { EzsignfoldersignerassociationResponseCompoundUser } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsignfoldersignerassociationResponseCompoundUser = {
    pkiUserID,
    fkiLanguageID,
    sUserFirstname,
    sUserLastname,
    sEmailAddress,
    eUserType,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
